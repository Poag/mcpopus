"""Plugin sources: add a git repository, install from the GUI, review and apply updates."""

import re
import subprocess
from pathlib import Path

import pytest

from mcpopus.sources import DEFAULT_URL, SourceError, Sources

from .oauth_helpers import say

PLUGIN = '''
from mcpopus.plugin import Plugin, tool

class P(Plugin):
    @tool(tier="read")
    async def who(self) -> str:
        return "I am {v}"

async def setup(host):
    await host.add_plugin(P(host.context))
'''
TOML = 'name = "{n}"\nversion = "{v}"\ndescription = "demo plugin {n}"\nmin_host_version = "0.1.0"\n'


def git(cwd, *args):
    subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false", *args], cwd=cwd, check=True,
                   capture_output=True, env={"PATH": "/usr/bin:/bin:/usr/local/bin", "HOME": str(cwd), "GIT_CONFIG_GLOBAL": "/dev/null"})


def write_plugin(repo: Path, name: str, version: str, body: str | None = None):
    d = repo / "plugins" / name
    d.mkdir(parents=True, exist_ok=True)
    (d / "plugin.toml").write_text(TOML.format(n=name, v=version))
    (d / "__init__.py").write_text(body if body is not None else PLUGIN.format(v=f"{name} {version}"))


@pytest.fixture
def origin(tmp_path):
    repo = tmp_path / "origin"
    repo.mkdir()
    git(repo, "init", "-q", "-b", "main")
    write_plugin(repo, "demo", "1.0.0")
    write_plugin(repo, "other", "1.0.0")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "first")
    return repo


def commit(repo: Path, msg: str):
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", msg)


async def add_source(running, c, csrf, origin):
    running.host.sources.allow_file = True
    r = await c.post("/sources/add", data={"csrf": csrf, "url": f"file://{origin}", "ref": "main", "trust": "1"})
    assert r.status_code == 303
    return running.host.sources.make_id(f"file://{origin}", "main")


def test_default_source_is_listed_but_not_fetched(tmp_path):
    s = Sources(tmp_path / "c", tmp_path / "d")
    (view,) = s.view()
    assert view["url"] == DEFAULT_URL == "https://github.com/Poag/mcpopus-plugins" and view["default"] and not view["fetched"]
    assert Sources(tmp_path / "c", tmp_path / "d").view()[0]["id"] == view["id"]  # stable across restarts
    s.remove(view["id"])
    assert Sources(tmp_path / "c", tmp_path / "d").view() == []  # a removed default stays removed


@pytest.mark.parametrize("url", ["http://github.com/a/b", "ssh://git@github.com/a/b", "git://github.com/a/b", "file:///tmp/x", "ext::sh -c id",
                                 "https://user:pw@github.com/a/b", "https://github.com/a/b?x=1", "https://github.com/a/b#frag", "-oProxyCommand=id",
                                 "https://github.com/a b", "", "https://", "git@github.com:a/b.git", "https://github.com/a/b\nhttps://x"])
def test_urls_that_are_refused(tmp_path, url):
    with pytest.raises(SourceError):
        Sources(tmp_path / "c", tmp_path / "d").validate_url(url)


@pytest.mark.parametrize("ref", ["--upload-pack=id", "-x", "a..b", "a b", "x;id", "a/", "", "$(id)"][:-1])
def test_refs_that_are_refused(tmp_path, ref):
    if ref == "":
        assert Sources.validate_ref(ref) == "main"
        return
    with pytest.raises(SourceError):
        Sources.validate_ref(ref)


async def test_install_from_the_gui_and_use_the_plugin(running, origin):
    async with running.admin() as (c, csrf):
        sid = await add_source(running, c, csrf, origin)
        page = (await c.get("/plugins")).text
        assert "demo plugin demo" in page and "demo plugin other" in page and "I trust this code" in page
        # the confirmation is required
        r = await c.post("/plugins/demo/install", data={"csrf": csrf, "source": sid})
        assert r.status_code == 303 and "Tick the box" in (await c.get(r.headers["location"].split("#")[0])).text
        assert not running.host.manager.is_loaded("demo")
        r = await c.post("/plugins/demo/install", data={"csrf": csrf, "source": sid, "trust": "1"})
        assert running.host.manager.is_loaded("demo")
        assert "aria-label=\"Uninstall demo\"" in (await c.get("/plugins")).text  # only plugins installed from a source have the button
        assert await say(running, "demo", "who") == "I am demo 1.0.0"
        # survives a restart of the manager (installed plugins load from their checkout)
        await running.host.manager.stop()
        await running.host.manager.start()
        assert running.host.manager.is_loaded("demo") and not running.host.manager.is_loaded("other")
        # cannot remove a source that still has plugins installed
        r = await c.post(f"/sources/{sid}/remove", data={"csrf": csrf})
        assert "Uninstall the plugins" in (await c.get(r.headers["location"].split("#")[0])).text
        await c.post("/plugins/demo/uninstall", data={"csrf": csrf})
        assert not running.host.manager.is_loaded("demo") and "demo" not in running.host.sources.installed_paths()
        await c.post(f"/sources/{sid}/remove", data={"csrf": csrf})
        assert running.host.sources.view()[-1]["id"] != sid


async def test_updates_are_reviewed_then_applied_and_a_broken_one_keeps_the_old_version(running, origin):
    async with running.admin() as (c, csrf):
        sid = await add_source(running, c, csrf, origin)
        await c.post("/plugins/demo/install", data={"csrf": csrf, "source": sid, "trust": "1"})
        first = running.host.sources._source(sid)["applied"]
        write_plugin(origin, "demo", "1.1.0")
        commit(origin, "demo 1.1.0")
        await c.post(f"/sources/{sid}/fetch", data={"csrf": csrf})
        src = running.host.sources._source(sid)
        assert src["applied"] == first and src["head"] != first  # fetching alone changes nothing that runs
        assert await say(running, "demo", "who") == "I am demo 1.0.0"
        page = (await c.get("/plugins")).text
        assert "Update available" in page and "demo 1.1.0" in page and "plugins/demo/plugin.toml" in page
        r = await c.post(f"/sources/{sid}/apply", data={"csrf": csrf})  # no confirmation
        assert running.host.sources._source(sid)["applied"] == first
        await c.post(f"/sources/{sid}/apply", data={"csrf": csrf, "trust": "1"})
        assert running.host.sources._source(sid)["applied"] == src["head"]
        assert await say(running, "demo", "who") == "I am demo 1.1.0"
        # a broken update: applied, but the reload fails and the running version stays
        write_plugin(origin, "demo", "1.2.0", body="def broken(:\n")
        commit(origin, "broken")
        await c.post(f"/sources/{sid}/fetch", data={"csrf": csrf})
        r = await c.post(f"/sources/{sid}/apply", data={"csrf": csrf, "trust": "1"})
        assert "demo failed" in (await c.get(r.headers["location"].split("#")[0])).text
        assert running.host.manager.is_loaded("demo") and await say(running, "demo", "who") == "I am demo 1.1.0"


async def test_a_plugin_in_the_plugins_volume_wins_and_blocks_installing_the_same_name(running, origin):
    async with running.admin() as (c, csrf):
        sid = await add_source(running, c, csrf, origin)
        (running.plugins_dir / "demo").mkdir()
        (running.plugins_dir / "demo" / "plugin.toml").write_text(TOML.format(n="demo", v="9.9.9"))
        r = await c.post("/plugins/demo/install", data={"csrf": csrf, "source": sid, "trust": "1"})
        assert "already in the plugins directory" in (await c.get(r.headers["location"].split("#")[0])).text
        assert "demo" not in running.host.sources.installed_paths()


async def test_bad_sources_fail_cleanly(running, tmp_path):
    running.host.sources.allow_file = True
    async with running.admin() as (c, csrf):
        for url, ref in ((f"file://{tmp_path}/nothing-here", "main"), ("http://example.com/x", "main"), ("https://github.com/a/b", "--upload-pack=id")):
            r = await c.post("/sources/add", data={"csrf": csrf, "url": url, "ref": ref, "trust": "1"})
            assert r.status_code == 303
            assert "Could not add the source" in (await c.get(r.headers["location"].split("#")[0])).text
        r = await c.post("/sources/add", data={"csrf": csrf, "url": "https://github.com/a/b", "ref": "main"})  # no trust tick
        assert "Tick the box" in (await c.get(r.headers["location"].split("#")[0])).text
        r = await c.post("/sources/zzzz/fetch", data={"csrf": csrf})
        assert r.status_code == 404
    assert len(running.host.sources.view()) == 2  # the default and the one that was added before the clone failed


async def test_symlinks_in_a_repository_are_not_followed(running, origin, tmp_path):
    secret = tmp_path / "outside.txt"
    secret.write_text("TOP-SECRET")
    (origin / "plugins" / "linked").symlink_to(tmp_path)
    (origin / "plugins" / "demo" / "leak.txt").symlink_to(secret)
    commit(origin, "symlinks")
    async with running.admin() as (c, csrf):
        sid = await add_source(running, c, csrf, origin)
        repo = running.host.sources.repo_dir(sid)
        assert not (repo / "plugins" / "demo" / "leak.txt").is_symlink() and "TOP-SECRET" not in (repo / "plugins" / "demo" / "leak.txt").read_text()
        assert [p.name for p in running.host.sources.available(sid) if not p.problem] == ["demo", "other"]
        assert "linked" not in [p.name for p in running.host.sources.available(sid) if not p.problem]


async def test_page_escapes_repository_text(running, origin):
    write_plugin(origin, "demo", "1.0.0")
    (origin / "plugins" / "demo" / "plugin.toml").write_text('name = "demo"\nversion = "1"\ndescription = "<script>alert(1)</script>"\n')
    commit(origin, "xss")
    async with running.admin() as (c, csrf):
        await add_source(running, c, csrf, origin)
        page = (await c.get("/plugins")).text
        assert "<script>alert(1)</script>" not in page and "&lt;script&gt;" in page


async def test_update_panel_only_shows_when_an_update_exists(running, origin):
    async with running.admin() as (c, csrf):
        assert "Update available" not in (await c.get("/plugins")).text  # the default source has not even been fetched
        sid = await add_source(running, c, csrf, origin)
        assert "Update available" not in (await c.get("/plugins")).text  # fetched and current
        write_plugin(origin, "demo", "1.1.0")
        commit(origin, "demo 1.1.0")
        await c.post(f"/sources/{sid}/fetch", data={"csrf": csrf})
        assert "Update available" in (await c.get("/plugins")).text
