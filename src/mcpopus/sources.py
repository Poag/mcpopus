"""Plugin sources: git repositories the admin can browse and install plugins from.

Plugins are code that runs inside the host, so nothing here is automatic:

* a repository is added deliberately (https only, no credentials in the URL);
* "fetch" only downloads; the plugins that are installed keep running the commit that was *applied*;
* an update is shown (new commits, changed files) and applied only when the admin says so;
* installing a plugin is its own step.

Repositories are checked out under <data>/sources/<id>/repo. Installed plugins are loaded straight from there
(the manager's extra search path), so there is no second copy to drift. A plugin directory in the plugins volume
with the same name always wins over an installed one.

git is run without a shell, with a fixed argument layout, with hooks, symlinks, prompts, system and user config
and every protocol except https switched off. Layout expected: <repo>/plugins/<name>/{plugin.toml,__init__.py}.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import re
import shutil
import threading
import time
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from .packages import parse_requirements
from .routing import valid_plugin_name

log = logging.getLogger("mcpopus.sources")
DEFAULT_URL = "https://github.com/Poag/mcpopus-plugins"
DEFAULT_REF = "main"
MAX_SOURCES = 10
MAX_REPO_BYTES = 50 * 1024 * 1024
GIT_TIMEOUT = 180.0
REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,99}$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")


class SourceError(Exception):
    """Message is safe to show in the admin UI."""


@dataclass
class PluginInfo:
    name: str
    version: str
    description: str
    installed: bool
    problem: str = ""
    requirements: list[str] = field(default_factory=list)


class Sources:
    def __init__(self, config_dir: Path, data_dir: Path, default_url: str = DEFAULT_URL, allow_file: bool = False) -> None:
        self.path = config_dir / "sources.json"
        self.root = data_dir / "sources"
        self.home = data_dir / "run" / "githome"
        self.allow_file = allow_file  # tests only: lets a local repository stand in for a remote one
        self._lock = threading.Lock()
        self._locks: dict[str, asyncio.Lock] = {}
        config_dir.mkdir(parents=True, exist_ok=True)
        if not self.path.exists() and default_url:
            sid = self.make_id(default_url, DEFAULT_REF)
            self._save({"sources": {sid: {"url": default_url, "ref": DEFAULT_REF, "applied": "", "head": "", "fetched_at": 0, "default": True}}, "installed": {}})

    # ------------------------------------------------------------ persistence
    def _load(self) -> dict:
        try:
            return json.loads(self.path.read_text())
        except FileNotFoundError:
            return {"sources": {}, "installed": {}}

    def _save(self, data: dict) -> None:
        tmp = self.path.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, indent=2, sort_keys=True)
        os.replace(tmp, self.path)

    @staticmethod
    def make_id(url: str, ref: str) -> str:
        return hashlib.sha256(f"{url}\0{ref}".encode()).hexdigest()[:12]

    def repo_dir(self, sid: str) -> Path:
        return self.root / sid / "repo"

    # -------------------------------------------------------------- validation
    def validate_url(self, url: str) -> str:
        url = url.strip()
        if not url or len(url) > 300 or any(c.isspace() or ord(c) < 32 for c in url) or url.startswith("-"):
            raise SourceError("That is not a valid repository URL.")
        parts = urlsplit(url)
        scheme_ok = parts.scheme == "https" or (self.allow_file and parts.scheme == "file")
        if not scheme_ok:
            raise SourceError("Only https:// repository URLs are accepted.")
        if parts.scheme == "https" and not parts.hostname:
            raise SourceError("That is not a valid repository URL.")
        if parts.username or parts.password:
            raise SourceError("Do not put credentials in the URL. Only public repositories are supported.")
        if parts.query or parts.fragment:
            raise SourceError("The URL must not have a query or fragment.")
        return url.rstrip("/")

    @staticmethod
    def validate_ref(ref: str) -> str:
        ref = ref.strip() or DEFAULT_REF
        if not REF_RE.fullmatch(ref) or ".." in ref or ref.endswith((".lock", "/")) or "//" in ref:
            raise SourceError("The branch or tag name is not valid.")
        return ref

    # ------------------------------------------------------------------- crud
    def add(self, url: str, ref: str) -> str:
        url, ref = self.validate_url(url), self.validate_ref(ref)
        with self._lock:
            data = self._load()
            sid = self.make_id(url, ref)
            if sid in data["sources"]:
                raise SourceError("That repository and branch are already listed.")
            if len(data["sources"]) >= MAX_SOURCES:
                raise SourceError(f"At most {MAX_SOURCES} sources.")
            data["sources"][sid] = {"url": url, "ref": ref, "applied": "", "head": "", "fetched_at": 0, "default": False}
            self._save(data)
        return sid

    def remove(self, sid: str) -> None:
        with self._lock:
            data = self._load()
            if sid not in data["sources"]:
                raise SourceError("No such source.")
            if any(v["source"] == sid for v in data["installed"].values()):
                raise SourceError("Uninstall the plugins that came from this source first.")
            del data["sources"][sid]
            self._save(data)
        shutil.rmtree(self.root / sid, ignore_errors=True)

    def _source(self, sid: str) -> dict:
        s = self._load()["sources"].get(sid)
        if s is None:
            raise SourceError("No such source.")
        return s

    def _update(self, sid: str, **fields) -> None:
        with self._lock:
            data = self._load()
            data["sources"][sid].update(fields)
            self._save(data)

    # -------------------------------------------------------------------- git
    def _env(self) -> dict[str, str]:
        self.home.mkdir(parents=True, exist_ok=True)
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(self.home), "LC_ALL": "C", "GIT_TERMINAL_PROMPT": "0",
            "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_ALLOW_PROTOCOL": "https:file" if self.allow_file else "https",
        }
        for k in ("HTTPS_PROXY", "https_proxy", "NO_PROXY", "no_proxy", "SSL_CERT_FILE", "SSL_CERT_DIR"):
            if k in os.environ:
                env[k] = os.environ[k]
        return env

    async def _git(self, args: list[str], cwd: Path) -> str:
        cmd = ["git", "-c", "core.hooksPath=/dev/null", "-c", "core.symlinks=false", "-c", "core.fsmonitor=false",
               "-c", "advice.detachedHead=false", "-c", "gc.auto=0", *args]
        try:
            proc = await asyncio.create_subprocess_exec(*cmd, cwd=cwd, env=self._env(), stdin=asyncio.subprocess.DEVNULL,
                                                        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        except FileNotFoundError:
            raise SourceError("git is not installed in this container.") from None
        try:
            out, err = await asyncio.wait_for(proc.communicate(), GIT_TIMEOUT)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            raise SourceError("git took too long and was stopped.") from None
        if proc.returncode != 0:
            first = (err.decode("utf-8", "replace").strip().splitlines() or ["git failed"])[-1][:200]
            log.warning("git %s failed: %s", args[0], first)
            raise SourceError(f"git {args[0]} failed: {first}")
        return out.decode("utf-8", "replace")[:200_000]

    def _glock(self, sid: str) -> asyncio.Lock:
        return self._locks.setdefault(sid, asyncio.Lock())

    async def _rev(self, d: Path, what: str) -> str:
        sha = (await self._git(["rev-parse", "--verify", what], d)).strip()
        if not SHA_RE.fullmatch(sha):
            raise SourceError("git returned an unexpected value.")
        return sha

    async def fetch(self, sid: str) -> dict:
        """Download. Never changes what is checked out, except the very first time (nothing installed yet)."""
        src = self._source(sid)
        async with self._glock(sid):
            d = self.repo_dir(sid)
            if not (d / ".git").exists():
                shutil.rmtree(d.parent, ignore_errors=True)
                d.parent.mkdir(parents=True, exist_ok=True)
                await self._git(["clone", "--no-checkout", "--depth", "100", "--single-branch", "--branch", src["ref"], "--", src["url"], str(d)], d.parent)
                head = await self._rev(d, "HEAD")
                await self._git(["checkout", "--detach", "-f", head], d)
                applied = head
            else:
                await self._git(["fetch", "--depth", "100", "origin", src["ref"]], d)
                head = await self._rev(d, "FETCH_HEAD")
                applied = src["applied"] or head
                if not src["applied"]:
                    await self._git(["checkout", "--detach", "-f", head], d)
            self._check_size(d)
            self._update(sid, head=head, applied=applied, fetched_at=int(time.time()))
        return await self.pending(sid)

    async def pending(self, sid: str) -> dict:
        """What an update would change: commit list and file summary. Empty when up to date."""
        src = self._source(sid)
        applied, head = src["applied"], src["head"]
        if not applied or not head or applied == head:
            return {}
        d = self.repo_dir(sid)
        try:
            log_ = (await self._git(["log", "--no-color", "--format=%h %s", "-n", "30", f"{applied}..{head}"], d)).strip()
            stat = (await self._git(["diff", "--no-color", "--stat=100", applied, head], d)).strip()
        except SourceError:
            log_, stat = "(history for this range is not available locally)", ""
        return {"log": log_[:4000], "stat": stat[:6000]}

    async def apply(self, sid: str) -> list[str]:
        """Check out the fetched head. Returns the installed plugins from this source, which should be reloaded."""
        src = self._source(sid)
        if not src["head"] or src["head"] == src["applied"]:
            raise SourceError("There is no update to apply.")
        async with self._glock(sid):
            d = self.repo_dir(sid)
            await self._git(["checkout", "--detach", "-f", src["head"]], d)
            await self._git(["clean", "-fdxq"], d)
            try:
                self._check_size(d)
            except SourceError:
                await self._git(["checkout", "--detach", "-f", src["applied"]], d)
                raise
            self._update(sid, applied=src["head"])
        return [n for n, v in self._load()["installed"].items() if v["source"] == sid]

    @staticmethod
    def _check_size(d: Path) -> None:
        total = 0
        for root, dirs, files in os.walk(d):
            dirs[:] = [x for x in dirs if x != ".git"]
            total += sum((Path(root) / f).stat().st_size for f in files if (Path(root) / f).is_file())
            if total > MAX_REPO_BYTES:
                raise SourceError("The repository is larger than the 50 MB limit.")

    # -------------------------------------------------------------- plugins
    def available(self, sid: str) -> list[PluginInfo]:
        d = self.repo_dir(sid) / "plugins"
        installed = self._load()["installed"]
        out: list[PluginInfo] = []
        if not d.is_dir():
            return out
        for p in sorted(d.iterdir()):
            if not p.is_dir() or p.is_symlink() or p.name.startswith((".", "_")):
                continue
            try:
                m = tomllib.loads((p / "plugin.toml").read_text())
                problem = "" if m.get("name") == p.name and valid_plugin_name(p.name) and (p / "__init__.py").is_file() else "not a valid plugin directory"
                reqs: list[str] = []
                try:
                    reqs = parse_requirements(m.get("requirements"))
                except ValueError as e:
                    problem = problem or f"invalid requirements: {e}"
                out.append(PluginInfo(p.name, str(m.get("version", "?"))[:20], str(m.get("description", ""))[:300], installed.get(p.name, {}).get("source") == sid, problem, reqs))
            except (OSError, tomllib.TOMLDecodeError):
                out.append(PluginInfo(p.name[:40], "?", "", False, "plugin.toml is missing or unreadable"))
        return out

    def install(self, name: str, sid: str, manual_dir: Path) -> None:
        if not valid_plugin_name(name):
            raise SourceError("Invalid plugin name.")
        info = next((i for i in self.available(sid) if i.name == name), None)
        if info is None or info.problem:
            raise SourceError("That plugin is not available from this source.")
        if (manual_dir / name).exists():
            raise SourceError("A plugin with this name is already in the plugins directory, which takes priority.")
        with self._lock:
            data = self._load()
            other = data["installed"].get(name)
            if other and other["source"] != sid:
                raise SourceError("That name is already installed from another source.")
            data["installed"][name] = {"source": sid}
            self._save(data)

    def uninstall(self, name: str) -> None:
        with self._lock:
            data = self._load()
            if data["installed"].pop(name, None) is None:
                raise SourceError("That plugin was not installed from a source.")
            self._save(data)

    def installed_paths(self) -> dict[str, Path]:
        out = {}
        for name, v in self._load()["installed"].items():
            p = self.repo_dir(v["source"]) / "plugins" / name
            if valid_plugin_name(name) and p.is_dir() and not p.is_symlink():
                out[name] = p
        return out

    def view(self) -> list[dict]:
        data = self._load()
        return [{"id": sid, **s, "fetched": bool(s["applied"]), "plugins": self.available(sid) if s["applied"] else [],
                 "has_update": bool(s["head"] and s["applied"] and s["head"] != s["applied"]),
                 "browse": s["url"] if s["url"].startswith("https://github.com/") else ""} for sid, s in data["sources"].items()]
