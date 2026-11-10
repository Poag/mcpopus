"""Python packages a plugin asks for (`requirements` in plugin.toml), installed by the host when the plugin is added.

Safety rules, all enforced here:
  * Each requirement is an exact pin, `name==version`, optionally with `--hash=sha256:...` values. No ranges, extras, URLs,
    VCS references, local paths or pip options.
  * Only wheels are installed (`--only-binary :all:`), so nothing runs at install time (no setup.py, no build backend).
    The code in a wheel runs when the plugin imports it, inside the host: the same trust as the plugin itself.
  * Installation happens only on the owner's action (installing the plugin, applying its update, or the button on its page),
    never on load. A plugin whose packages are not installed does not load.
  * Packages go into a private directory per plugin and requirement set, under the data volume. pip runs with `--isolated` and a
    cleaned environment (no MCPOPUS_* variables, so the secret key is never visible to it), a timeout, and bounded output.
  * A package the host already provides is never replaced: asking for another version is refused with a clear message.
  * `MCPOPUS_ALLOW_PACKAGE_INSTALL=false` switches installing off entirely.
"""

from __future__ import annotations

import asyncio
import hashlib
import importlib.metadata
import importlib.util
import json
import logging
import os
import re
import shutil
import sys
import tempfile
import time
from pathlib import Path

log = logging.getLogger("mcpopus.packages")

MAX_REQUIREMENTS = 20
INSTALL_TIMEOUT = 300.0
REQ_RE = re.compile(r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]{0,99})==(?P<version>[A-Za-z0-9][A-Za-z0-9._+!-]{0,49})(?P<hashes>(?: +--hash=sha256:[0-9a-f]{64})*)$")
_CTRL = re.compile(r"[\x00-\x1f\x7f]")


class PackageError(Exception):
    """The message is safe to show in the admin UI."""


def normalise(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_requirements(entries: object) -> list[str]:
    """Validate the manifest's list; return it normalised (single spaces). Raises ValueError with a safe message."""
    if entries in (None, []):
        return []
    if not isinstance(entries, list) or not all(isinstance(e, str) for e in entries):
        raise ValueError("requirements must be a list of strings")
    if len(entries) > MAX_REQUIREMENTS:
        raise ValueError(f"at most {MAX_REQUIREMENTS} requirements are allowed")
    out, seen, hashed = [], set(), 0
    for raw in entries:
        text = " ".join(raw.split())
        m = REQ_RE.fullmatch(text)
        if not m:
            shown = _CTRL.sub("?", raw)[:60]
            raise ValueError(f"requirement {shown!r} is not allowed: use an exact pin such as 'name==1.2.3', optionally followed by '--hash=sha256:<64 hex digits>'")
        key = normalise(m["name"])
        if key in seen:
            raise ValueError(f"requirement {m['name']!r} is listed twice")
        seen.add(key)
        hashed += bool(m["hashes"])
        out.append(text)
    if hashed not in (0, len(out)):
        raise ValueError("either every requirement has a --hash or none does")
    return out


def fingerprint(requirements: list[str]) -> str:
    return hashlib.sha256("\n".join(sorted(requirements)).encode()).hexdigest()[:16]


def summary(requirements: list[str]) -> str:
    return ", ".join(r.split(" ")[0] for r in requirements)


class Packages:
    def __init__(self, data_dir: Path, enabled: bool = True, index_url: str = "", find_links: str = "") -> None:
        self.root = data_dir / "packages"
        self.enabled, self.index_url, self.find_links = enabled, index_url, find_links
        self._active: dict[str, tuple[str, dict[str, str]]] = {}  # plugin -> (fingerprint, {dist: version})
        self._owners: dict[str, tuple[str, str]] = {}  # dist -> (plugin, version) for everything on sys.path
        self._locks: dict[str, asyncio.Lock] = {}

    # ----------------------------------------------------------------- state
    def dir_for(self, plugin: str, requirements: list[str]) -> Path:
        return self.root / plugin / fingerprint(requirements)

    def installed(self, plugin: str, requirements: list[str]) -> dict[str, str] | None:
        marker = self.dir_for(plugin, requirements) / "installed.json"
        try:
            return json.loads(marker.read_text())["dists"]
        except (OSError, ValueError, KeyError):
            return None

    def status(self, plugin: str, requirements: list[str]) -> str:
        if not requirements:
            return "none"
        return "installed" if self.installed(plugin, requirements) is not None else "not installed"

    # ------------------------------------------------------------- activation
    def _host_versions(self) -> dict[str, str]:
        out = {}
        root = str(self.root)
        for dist in importlib.metadata.distributions():
            path = str(getattr(dist, "_path", "") or "")
            if path.startswith(root):
                continue
            name = dist.metadata["Name"]
            if name:
                out[normalise(name)] = dist.version
        return out

    def activate(self, plugin: str, requirements: list[str]) -> None:
        """Make an installed set importable by this plugin. Called on every load; raises PackageError with the reason."""
        dists = self.installed(plugin, requirements)
        if dists is None:
            raise PackageError(f"needs packages that are not installed yet ({summary(requirements)}). Install the plugin's packages from its page")
        fp = fingerprint(requirements)
        active = self._active.get(plugin)
        if active and active[0] != fp:
            changed = [n for n, v in dists.items() if n in active[1] and active[1][n] != v]
            if changed:
                raise PackageError(f"its packages changed ({', '.join(sorted(changed))}) from versions already loaded in this process: restart the host to apply them")
        host = self._host_versions()
        for name, version in dists.items():
            if name in host and host[name] != version:
                raise PackageError(f"{name} {version} conflicts with {name} {host[name]}, which the host provides and a plugin cannot replace: ask for {host[name]} or leave it out")
            owner = self._owners.get(name)
            if owner and owner[0] != plugin and owner[1] != version:
                raise PackageError(f"{name} {version} conflicts with {name} {owner[1]} already loaded for the plugin {owner[0]}: two plugins cannot use different versions of one package")
        d = str(self.dir_for(plugin, requirements))
        if d not in sys.path:
            sys.path.append(d)  # appended: anything the host provides always wins
            importlib.invalidate_caches()
        for name, version in dists.items():
            self._owners[name] = (plugin, version)
        self._active[plugin] = (fp, dists)

    # --------------------------------------------------------------- install
    def _env(self, home: str) -> dict[str, str]:
        env = {k: v for k, v in os.environ.items() if not k.startswith(("MCPOPUS_", "PIP_", "PYTHON"))}
        env["HOME"] = home
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        return env

    def _command(self, target: str, reqfile: str, hashed: bool) -> list[str]:
        cmd = [sys.executable, "-m", "pip", "install", "--isolated", "--target", target, "--only-binary", ":all:", "--no-input",
               "--disable-pip-version-check", "--no-cache-dir", "--no-compile", "--progress-bar", "off", "-r", reqfile]
        if hashed:
            cmd.append("--require-hashes")
        if self.index_url == "none":
            cmd.append("--no-index")
        elif self.index_url:
            cmd += ["--index-url", self.index_url]
        if self.find_links:
            cmd += ["--find-links", self.find_links]
        return cmd

    @staticmethod
    def _reason(output: str) -> str:
        lines = [_CTRL.sub(" ", ln).strip() for ln in output.splitlines() if ln.strip()]
        errors = [ln for ln in lines if ln.startswith("ERROR:")] or lines[-2:]
        return " | ".join(e[:200] for e in errors[-2:]) or "pip gave no reason"

    async def install(self, plugin: str, requirements: list[str]) -> dict[str, str]:
        """Install a plugin's packages. Idempotent: an installed set is left as it is. Returns {distribution: version}."""
        if not requirements:
            return {}
        already = self.installed(plugin, requirements)
        if already is not None:
            return already
        if not self.enabled:
            raise PackageError("installing packages is switched off on this host (MCPOPUS_ALLOW_PACKAGE_INSTALL=false)")
        async with self._locks.setdefault(plugin, asyncio.Lock()):
            already = self.installed(plugin, requirements)
            if already is not None:
                return already
            base = self.root / plugin
            base.mkdir(parents=True, exist_ok=True, mode=0o700)
            work = Path(tempfile.mkdtemp(prefix=".tmp-", dir=base))
            try:
                reqfile = work / "requirements.txt"
                reqfile.write_text("\n".join(requirements) + "\n")
                target = work / "site"
                cmd = self._command(str(target), str(reqfile), all("--hash=" in r for r in requirements))
                log.info("installing packages for %s: %s", plugin, summary(requirements))
                started = time.monotonic()
                proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
                                                            env=self._env(str(work)), cwd=str(work))
                try:
                    out, _ = await asyncio.wait_for(proc.communicate(), INSTALL_TIMEOUT)
                except asyncio.TimeoutError:
                    proc.kill()
                    await proc.wait()
                    raise PackageError(f"installing packages took longer than {int(INSTALL_TIMEOUT)} seconds and was stopped") from None
                text = out[-20000:].decode("utf-8", "replace")
                if proc.returncode != 0:
                    log.warning("package install for %s failed: %s", plugin, self._reason(text))
                    raise PackageError(f"installing packages failed: {self._reason(text)}")
                dists = {}
                for info in target.glob("*.dist-info"):
                    stem = info.name[: -len(".dist-info")]
                    name, _, version = stem.rpartition("-")
                    if name:
                        dists[normalise(name)] = version
                (target / "installed.json").write_text(json.dumps({"requirements": requirements, "dists": dists}))
                final = self.dir_for(plugin, requirements)
                if final.exists():
                    shutil.rmtree(final)
                target.rename(final)
                log.info("packages for %s installed in %.1fs: %s", plugin, time.monotonic() - started, ", ".join(f"{n} {v}" for n, v in sorted(dists.items())))
                self._prune(plugin, keep=final.name)
                return dists
            finally:
                shutil.rmtree(work, ignore_errors=True)

    def _prune(self, plugin: str, keep: str) -> None:
        active = self._active.get(plugin, ("", {}))[0]
        for d in (self.root / plugin).iterdir():
            if d.is_dir() and not d.name.startswith(".") and d.name not in (keep, active):
                shutil.rmtree(d, ignore_errors=True)

    def remove(self, plugin: str) -> None:
        """Delete a plugin's installed packages (they remain importable in this process until it restarts)."""
        shutil.rmtree(self.root / plugin, ignore_errors=True)
