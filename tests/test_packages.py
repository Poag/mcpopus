"""Plugin requirements: strict parsing, install on add (wheels only, offline here), conflicts, approval, admin flow."""

import base64
import hashlib
import sys
import textwrap
import zipfile
from pathlib import Path

import pytest

from mcpopus.manager import PluginLoadError
from mcpopus.packages import PackageError, fingerprint, parse_requirements

from .conftest import make_plugin


def build_wheel(dest: Path, name: str, version: str, body: str, requires: str = "") -> Path:
    dist = f"{name}-{version}.dist-info"
    files = {f"{name}/__init__.py": body, f"{dist}/METADATA": f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n{requires}",
             f"{dist}/WHEEL": "Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\nTag: py3-none-any\n"}
    record = [f"{p},sha256={base64.urlsafe_b64encode(hashlib.sha256(c.encode()).digest()).rstrip(b'=').decode()},{len(c)}" for p, c in files.items()]
    record.append(f"{dist}/RECORD,,")
    files[f"{dist}/RECORD"] = "\n".join(record) + "\n"
    dest.mkdir(parents=True, exist_ok=True)
    path = dest / f"{name}-{version}-py3-none-any.whl"
    with zipfile.ZipFile(path, "w") as z:
        for p, c in files.items():
            z.writestr(p, c)
    return path


def offline(running, wheels: Path):
    pk = running.host.manager.packages
    pk.index_url, pk.find_links = "none", str(wheels)
    return pk


PLUGIN = textwrap.dedent('''
    from mcpopus.plugin import Plugin, tool

    class P(Plugin):
        @tool(tier="read")
        async def value(self) -> str:
            import %(mod)s
            return str(%(mod)s.VALUE)

    async def setup(host):
        await host.add_plugin(P(host.context))
''')


def test_requirement_parsing_is_strict():
    assert parse_requirements(None) == [] and parse_requirements(["Foo==1.0", "bar.baz==2.0.1"]) == ["Foo==1.0", "bar.baz==2.0.1"]
    h = "--hash=sha256:" + "a" * 64
    assert parse_requirements([f"foo==1.0   {h}"]) == [f"foo==1.0 {h}"]
    for bad in ("foo", "foo>=1", "foo~=1.0", "foo==1.*", "foo[extra]==1", "https://evil/x.whl", "git+https://x/y", "-r other.txt", "--index-url x",
                "foo==1.0; python_version>'3'", "./local", "foo @ https://x", "foo==1.0 --hash=md5:abc", "foo==1.0\nbar==2", "a" * 120 + "==1"):
        with pytest.raises(ValueError):
            parse_requirements([bad])
    with pytest.raises(ValueError):
        parse_requirements(["foo==1", "FOO==2"])  # duplicates, ignoring case
    with pytest.raises(ValueError):
        parse_requirements([f"foo==1.0 {h}", "bar==1.0"])  # hashes for all or none
    with pytest.raises(ValueError):
        parse_requirements([f"p{i}==1" for i in range(21)])
    assert fingerprint(["a==1", "b==2"]) == fingerprint(["b==2", "a==1"])


async def test_plugin_needing_packages_does_not_load_until_installed(running, tmp_path):
    offline(running, tmp_path / "wheels")
    build_wheel(tmp_path / "wheels", "mcpopus_demo_one", "1.0", "VALUE = 42\n")
    make_plugin(running.plugins_dir, "needy", PLUGIN % {"mod": "mcpopus_demo_one"}, extra_toml='requirements = ["mcpopus-demo-one==1.0"]\n')
    with pytest.raises(PluginLoadError, match="not installed yet"):
        await running.host.manager.load("needy")  # nothing is installed on load
    assert running.host.manager.packages.status("needy", running.host.manager.requirements("needy")) == "not installed"
    done = await running.host.manager.install_packages("needy")
    assert done == {"mcpopus-demo-one": "1.0"}
    await running.host.manager.load("needy")
    from .oauth_helpers import mcp

    async with mcp(running, "needy") as c:
        assert (await c.call_tool("value", {})).content[0].text == "42"
    assert str(running.host.manager.packages.dir_for("needy", ["mcpopus-demo-one==1.0"])) in sys.path
    assert await running.host.manager.install_packages("needy") == done  # idempotent


async def test_install_failures_are_reported_plainly(running, tmp_path):
    offline(running, tmp_path / "wheels")
    (tmp_path / "wheels").mkdir()
    make_plugin(running.plugins_dir, "missing", PLUGIN % {"mod": "nothing"}, extra_toml='requirements = ["not-in-the-index==9.9"]\n')
    with pytest.raises(PluginLoadError, match="installing packages failed"):
        await running.host.manager.install_packages("missing")
    assert not list((running.host.manager.packages.root / "missing").glob("*/installed.json"))  # a failed install leaves nothing behind
    assert not [d for d in (running.host.manager.packages.root / "missing").iterdir() if d.name.startswith(".tmp-")]
    running.host.manager.packages.enabled = False
    with pytest.raises(PluginLoadError, match="switched off"):
        await running.host.manager.install_packages("missing")


async def test_sdists_and_bad_manifests_are_refused(running, tmp_path):
    make_plugin(running.plugins_dir, "badreq", PLUGIN % {"mod": "x"}, extra_toml='requirements = ["git+https://example.com/x.git"]\n')
    with pytest.raises(PluginLoadError, match="invalid requirements in plugin.toml.*not allowed"):
        await running.host.manager.load("badreq")
    # only wheels: an sdist in the index is never built
    offline(running, tmp_path / "wheels")
    sdist = tmp_path / "wheels" / "onlysdist-1.0.tar.gz"
    sdist.parent.mkdir()
    sdist.write_bytes(b"not a real archive")
    make_plugin(running.plugins_dir, "sd", PLUGIN % {"mod": "onlysdist"}, extra_toml='requirements = ["onlysdist==1.0"]\n')
    with pytest.raises(PluginLoadError, match="installing packages failed"):
        await running.host.manager.install_packages("sd")


async def test_a_package_the_host_provides_cannot_be_replaced(running, tmp_path):
    import importlib.metadata as md

    host_version = md.version("jinja2")
    offline(running, tmp_path / "wheels")
    build_wheel(tmp_path / "wheels", "jinja2", "0.0.1", "VALUE = 1\n")
    make_plugin(running.plugins_dir, "clash", PLUGIN % {"mod": "jinja2"}, extra_toml='requirements = ["jinja2==0.0.1"]\n')
    await running.host.manager.install_packages("clash")
    with pytest.raises(PluginLoadError, match=f"conflicts with jinja2 {host_version}"):
        await running.host.manager.load("clash")


async def test_two_plugins_cannot_use_different_versions_of_one_package(running, tmp_path):
    offline(running, tmp_path / "wheels")
    build_wheel(tmp_path / "wheels", "mcpopus_shared", "1.0", "VALUE = 1\n")
    build_wheel(tmp_path / "wheels", "mcpopus_shared", "2.0", "VALUE = 2\n")
    make_plugin(running.plugins_dir, "one", PLUGIN % {"mod": "mcpopus_shared"}, extra_toml='requirements = ["mcpopus-shared==1.0"]\n')
    make_plugin(running.plugins_dir, "two", PLUGIN % {"mod": "mcpopus_shared"}, extra_toml='requirements = ["mcpopus-shared==2.0"]\n')
    await running.host.manager.install_packages("one")
    await running.host.manager.install_packages("two")
    await running.host.manager.load("one")
    with pytest.raises(PluginLoadError, match="already loaded for the plugin one"):
        await running.host.manager.load("two")


async def test_changed_requirements_need_a_restart_when_a_version_is_already_loaded(running, tmp_path):
    offline(running, tmp_path / "wheels")
    build_wheel(tmp_path / "wheels", "mcpopus_up", "1.0", "VALUE = 1\n")
    build_wheel(tmp_path / "wheels", "mcpopus_up", "2.0", "VALUE = 2\n")
    make_plugin(running.plugins_dir, "up", PLUGIN % {"mod": "mcpopus_up"}, extra_toml='requirements = ["mcpopus-up==1.0"]\n')
    await running.host.manager.install_packages("up")
    await running.host.manager.load("up")
    make_plugin(running.plugins_dir, "up", PLUGIN % {"mod": "mcpopus_up"}, extra_toml='requirements = ["mcpopus-up==2.0"]\n')
    await running.host.manager.install_packages("up")
    with pytest.raises(PluginLoadError, match="restart the host"):
        await running.host.manager.reload("up")
    assert running.host.manager.is_loaded("up")  # the old version keeps serving


async def test_pip_runs_without_the_hosts_secrets(running, tmp_path, monkeypatch):
    monkeypatch.setenv("MCPOPUS_SECRET_KEY", "super-secret-value")
    monkeypatch.setenv("PIP_INDEX_URL", "https://evil.example/")
    env = running.host.manager.packages._env(str(tmp_path))
    assert "MCPOPUS_SECRET_KEY" not in env and "PIP_INDEX_URL" not in env and env["HOME"] == str(tmp_path)
    cmd = running.host.manager.packages._command("/t", "/r.txt", False)
    assert "--only-binary" in cmd and ":all:" in cmd and "--isolated" in cmd and "--require-hashes" not in cmd
    assert "--require-hashes" in running.host.manager.packages._command("/t", "/r.txt", True)


async def test_admin_installs_packages_with_the_plugin_and_shows_them(running, tmp_path):
    offline(running, tmp_path / "wheels")
    build_wheel(tmp_path / "wheels", "mcpopus_demo_adm", "1.0", "VALUE = 7\n")
    make_plugin(running.plugins_dir, "adm", PLUGIN % {"mod": "mcpopus_demo_adm"}, extra_toml='requirements = ["mcpopus-demo-adm==1.0"]\n')
    async with running.admin() as (c, csrf):
        page = (await c.get("/plugins/adm")).text
        assert "Packages" in page and "mcpopus-demo-adm==1.0" in page and "not installed" in page
        r = await c.post("/plugins/adm/packages", data={"csrf": csrf})
        assert r.status_code == 303 and running.host.manager.is_loaded("adm")
        assert ">installed<" in (await c.get("/plugins/adm")).text
        r = await c.post("/plugins/adm/packages", data={"csrf": "wrong"})
        assert r.status_code == 403


async def test_installing_from_a_source_installs_the_packages_and_an_update_can_change_them(running, tmp_path):
    from .test_sources import PLUGIN as SRC_PLUGIN, add_source, commit, git, say

    offline(running, tmp_path / "wheels")
    build_wheel(tmp_path / "wheels", "mcpopus_src_pkg", "1.0", "VALUE = 1\n")
    build_wheel(tmp_path / "wheels", "mcpopus_src_extra", "1.0", "VALUE = 2\n")
    origin = tmp_path / "origin"
    d = origin / "plugins" / "srcplug"
    d.mkdir(parents=True)
    git(origin, "init", "-q", "-b", "main")
    (d / "__init__.py").write_text(SRC_PLUGIN.format(v="srcplug 1.0.0").replace("async def setup", "import mcpopus_src_pkg\nasync def setup", 1))
    (d / "plugin.toml").write_text('name = "srcplug"\nversion = "1.0.0"\ndescription = "needs a package"\nmin_host_version = "0.3.0"\nrequirements = ["mcpopus-src-pkg==1.0"]\n')
    commit(origin, "first")
    async with running.admin() as (c, csrf):
        sid = await add_source(running, c, csrf, origin)
        page = (await c.get("/plugins")).text
        assert "mcpopus-src-pkg==1.0" in page and "and its packages" in page  # the owner sees them before ticking the trust box
        r = await c.post("/plugins/srcplug/install", data={"csrf": csrf, "source": sid})  # no trust box: nothing is installed
        assert not running.host.manager.packages.installed("srcplug", ["mcpopus-src-pkg==1.0"])
        r = await c.post("/plugins/srcplug/install", data={"csrf": csrf, "source": sid, "trust": "1"})
        assert running.host.manager.packages.installed("srcplug", ["mcpopus-src-pkg==1.0"]) == {"mcpopus-src-pkg": "1.0"}
        assert running.host.manager.is_loaded("srcplug")
        # an update that asks for one more package: fetched, reviewed, then installed with the apply
        (d / "plugin.toml").write_text('name = "srcplug"\nversion = "1.1.0"\ndescription = "needs two"\nmin_host_version = "0.3.0"\nrequirements = ["mcpopus-src-pkg==1.0", "mcpopus-src-extra==1.0"]\n')
        commit(origin, "more packages")
        await c.post(f"/sources/{sid}/fetch", data={"csrf": csrf})
        assert running.host.manager.packages.installed("srcplug", ["mcpopus-src-pkg==1.0", "mcpopus-src-extra==1.0"]) is None  # fetch installs nothing
        await c.post(f"/sources/{sid}/apply", data={"csrf": csrf, "trust": "1"})
        assert running.host.manager.packages.installed("srcplug", ["mcpopus-src-pkg==1.0", "mcpopus-src-extra==1.0"]) is not None
        assert running.host.manager.is_loaded("srcplug")
        await c.post("/plugins/srcplug/uninstall", data={"csrf": csrf})
        assert not (running.host.manager.packages.root / "srcplug").exists()
