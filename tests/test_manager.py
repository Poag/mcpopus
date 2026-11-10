"""Phase 1: load, unload, reload, failure isolation, dispatch."""

import sys
import textwrap

import pytest

from mcpopus import manager as manager_mod
from mcpopus.manager import PluginLoadError

from .conftest import make_plugin
from .oauth_helpers import get_tokens, mcp, say

GOOD = textwrap.dedent('''
    from mcpopus.plugin import Plugin, tool

    VERSION = "{v}"

    class P(Plugin):
        @tool(tier="read")
        async def who(self) -> str:
            return "I am {v}"

    async def setup(host):
        await host.add_plugin(P(host.context))
    {teardown}
''')
TEARDOWN_MARK = '''
async def teardown(host):
    open(host.context.data_dir / "torn-down", "w").write("yes")
'''


def good(v="v1", teardown=""):
    return GOOD.format(v=v, teardown=teardown)


async def test_load_unload_and_registry(running):
    mgr = running.host.manager
    make_plugin(running.plugins_dir, "alpha", good("v1"))
    st = await mgr.load("alpha")
    assert st.status == "loaded" and st.tools == ["who"] and mgr.is_loaded("alpha")
    assert await say(running, "alpha", "who") == "I am v1"
    await mgr.unload("alpha")
    assert not mgr.is_loaded("alpha") and mgr.states["alpha"].status == "unloaded"
    async with running.client() as c:
        r = await c.post("/alpha", json={})
        assert r.status_code == 401  # unloaded looks like unknown
    with pytest.raises(PluginLoadError):
        await mgr.unload("alpha")
    await mgr.load("alpha")
    with pytest.raises(PluginLoadError, match="already loaded"):
        await mgr.load("alpha")


async def test_loading_one_plugin_does_not_disturb_another(running):
    mgr = running.host.manager
    make_plugin(running.plugins_dir, "alpha", good("a"))
    make_plugin(running.plugins_dir, "beta", good("b"))
    await mgr.load("alpha")
    async with mcp(running, "hello") as hello:
        await mgr.load("beta")
        await mgr.reload("alpha")
        await mgr.unload("beta")
        assert (await hello.call_tool("say_hello", {"name": "x"})).content[0].text == "Hello, x!"


async def test_reload_picks_up_new_code(running):
    mgr = running.host.manager
    d = make_plugin(running.plugins_dir, "alpha", good("v1"))
    await mgr.load("alpha")
    tok = (await get_tokens(running, "alpha"))[1]
    assert await say(running, "alpha", "who", tok=tok) == "I am v1"
    (d / "__init__.py").write_text(good("v2"))
    await mgr.reload("alpha")
    assert await say(running, "alpha", "who", tok=tok) == "I am v2"  # same token still valid across reload
    assert not [m for m in sys.modules if m.startswith("mcpopus_plugin_alpha_g") and m != mgr.get("alpha").module_prefix]


async def test_setup_raising_is_isolated(running):
    mgr = running.host.manager
    make_plugin(running.plugins_dir, "bad", "async def setup(host):\n    raise RuntimeError('secret-looking detail')\n")
    with pytest.raises(PluginLoadError) as e:
        await mgr.load("bad")
    assert "RuntimeError" in str(e.value) and "secret-looking" not in str(e.value)
    assert mgr.states["bad"].status == "error" and not mgr.is_loaded("bad")
    assert not [m for m in sys.modules if m.startswith("mcpopus_plugin_bad_")]
    assert await say(running, "hello", "say_hello") == "Hello, world!"


async def test_start_loads_the_good_ones_when_one_is_broken(running):
    mgr = running.host.manager
    make_plugin(running.plugins_dir, "bad", "raise ImportError('nope')\n")
    make_plugin(running.plugins_dir, "good", good())
    await mgr.stop()
    await mgr.start()
    assert mgr.is_loaded("good") and mgr.is_loaded("hello") and not mgr.is_loaded("bad")
    assert mgr.states["bad"].status == "error"


async def test_teardown_raising_is_ignored_on_unload(running):
    mgr = running.host.manager
    make_plugin(running.plugins_dir, "alpha", good() + "\nasync def teardown(host):\n    raise RuntimeError('boom')\n")
    await mgr.load("alpha")
    st = await mgr.unload("alpha")
    assert st.status == "unloaded" and not mgr.is_loaded("alpha")


async def test_teardown_runs_and_old_teardown_error_does_not_fail_reload(running):
    mgr = running.host.manager
    d = make_plugin(running.plugins_dir, "alpha", good("v1", TEARDOWN_MARK))
    await mgr.load("alpha")
    await mgr.reload("alpha")
    assert (running.settings.data_dir / "plugins" / "alpha" / "torn-down").read_text() == "yes"
    (d / "__init__.py").write_text(good("v2") + "\nasync def teardown(host):\n    raise RuntimeError('boom')\n")
    await mgr.reload("alpha")  # v2 loads
    (d / "__init__.py").write_text(good("v3"))
    st = await mgr.reload("alpha")  # v2's failing teardown is ignored
    assert st.status == "loaded" and await say(running, "alpha", "who") == "I am v3"


async def test_failed_reload_keeps_previous_version_serving(running):
    mgr = running.host.manager
    d = make_plugin(running.plugins_dir, "alpha", good("v1"))
    await mgr.load("alpha")
    tok = (await get_tokens(running, "alpha"))[1]
    async with mcp(running, "alpha", tok=tok) as live:  # a client connected before the bad reload
        for broken in (
            "async def setup(host):\n    raise RuntimeError('x')\n",  # raises in setup
            "def nope(:\n",  # syntax error
            "x = 1\n",  # no setup
            good("v9") + "\nraise ValueError('at import')\n",  # raises at import
        ):
            (d / "__init__.py").write_text(broken)
            with pytest.raises(PluginLoadError):
                await mgr.reload("alpha")
            assert mgr.states["alpha"].status == "loaded"
            assert "previous version still running" in mgr.states["alpha"].error
            assert (await live.call_tool("who", {})).content[0].text == "I am v1"
        # and the next good reload clears the error
        (d / "__init__.py").write_text(good("v2"))
        await mgr.reload("alpha")
        assert mgr.states["alpha"].error is None
    assert await say(running, "alpha", "who", tok=tok) == "I am v2"


async def test_failed_reload_bad_manifest_and_host_version(running):
    mgr = running.host.manager
    d = make_plugin(running.plugins_dir, "alpha", good("v1"))
    await mgr.load("alpha")
    (d / "plugin.toml").write_text('name = "alpha"\nversion = "1"\ndescription = "x"\nmin_host_version = "99.0.0"\n')
    with pytest.raises(PluginLoadError, match="needs host"):
        await mgr.reload("alpha")
    (d / "plugin.toml").write_text('name = "other"\nversion = "1.0.0"\ndescription = "x"\n')
    with pytest.raises(PluginLoadError, match="does not match"):
        await mgr.reload("alpha")
    (d / "plugin.toml").write_text("not toml [")
    with pytest.raises(PluginLoadError, match="plugin.toml"):
        await mgr.reload("alpha")
    assert await say(running, "alpha", "who") == "I am v1"


async def test_setup_must_register_exactly_one_plugin(running):
    mgr = running.host.manager
    make_plugin(running.plugins_dir, "none", "async def setup(host):\n    pass\n")
    make_plugin(running.plugins_dir, "twice", good().replace("await host.add_plugin(P(host.context))", "await host.add_plugin(P(host.context))\n    await host.add_plugin(P(host.context))"))
    for n in ("none", "twice"):
        with pytest.raises(PluginLoadError):
            await mgr.load(n)


async def test_failure_after_setup_calls_teardown_to_release_resources(running):
    mgr = running.host.manager
    src = textwrap.dedent('''
        from mcpopus.plugin import Plugin, tool
        class P(Plugin):
            @tool(tier="read")
            async def a(self) -> str: return "a"
            @tool(tier="read", name="a")
            async def b(self) -> str: return "b"
        async def setup(host):
            await host.add_plugin(P(host.context))
        async def teardown(host):
            open(host.context.data_dir / "torn-down", "w").write("yes")
    ''')
    make_plugin(running.plugins_dir, "dupe", src)
    with pytest.raises(PluginLoadError, match="duplicate"):
        await mgr.load("dupe")
    assert (running.settings.data_dir / "plugins" / "dupe" / "torn-down").exists()


async def test_setup_timeout(running, monkeypatch):
    monkeypatch.setattr(manager_mod, "SETUP_TIMEOUT", 0.2)
    make_plugin(running.plugins_dir, "slow", "import asyncio\nasync def setup(host):\n    await asyncio.sleep(5)\n")
    with pytest.raises(PluginLoadError, match="timed out"):
        await running.host.manager.load("slow")


async def test_bad_directory_names_and_traversal_are_not_plugins(running):
    for n in ("Bad Name", "-x", "UPPER", "oauth", "a" * 40, "..hidden"):
        make_plugin(running.plugins_dir, n, good())
    names = running.host.manager.discover()
    assert names == ["hello"]
    async with running.client() as c:
        assert (await c.post("/oauth", json={})).status_code == 404


async def test_config_validation_error_does_not_leak_values(running):
    mgr = running.host.manager
    make_plugin(running.plugins_dir, "needy", textwrap.dedent('''
        from mcpopus.plugin import BaseModel, Plugin, SecretStr
        class Config(BaseModel):
            password: SecretStr
            port: int
        class P(Plugin): pass
        async def setup(host): await host.add_plugin(P(host.context))
    '''))
    running.host.configs.save("needy", values={"port": "not-a-number-SENTINEL"}, new_secrets={"password": "hunter2-SENTINEL"})
    with pytest.raises(PluginLoadError) as e:
        await mgr.load("needy")
    assert "SENTINEL" not in str(e.value) and "port" in str(e.value)


async def test_in_flight_request_is_drained_before_old_version_is_stopped(running):
    import asyncio

    mgr = running.host.manager
    src = textwrap.dedent('''
        import asyncio
        from mcpopus.plugin import Plugin, tool
        class P(Plugin):
            @tool(tier="read")
            async def slow(self) -> str:
                await asyncio.sleep(0.8)
                return "finished"
        async def setup(host): await host.add_plugin(P(host.context))
    ''')
    make_plugin(running.plugins_dir, "slowtool", src)
    await mgr.load("slowtool")
    tok = (await get_tokens(running, "slowtool"))[1]
    async with mcp(running, "slowtool", tok=tok) as c:
        call = asyncio.create_task(c.call_tool("slow", {}))
        await asyncio.sleep(0.3)
        await mgr.reload("slowtool")
        assert (await call).content[0].text == "finished"


async def test_legacy_session_survives_a_reload_when_stateless(running):
    """The default (stateless HTTP): a client connected before a reload, or before a host restart, carries on. There is no
    server-side session to lose."""
    mgr = running.host.manager
    make_plugin(running.plugins_dir, "alpha", good("v1"))
    await mgr.load("alpha")
    tok = (await get_tokens(running, "alpha"))[1]
    async with mcp(running, "alpha", mode="legacy", tok=tok) as old:
        await old.list_tools()
        await mgr.reload("alpha")
        assert (await old.call_tool("who", {})).content[0].text == "I am v1"


async def test_legacy_session_after_reload_when_sessions_are_on(running):
    """Observed behaviour with MCPOPUS_STATELESS_HTTP=false, recorded in BUILD_LOG: a legacy (session-based) client connected
    before a reload cannot continue (the host answers 404 Session not found); a new connection works."""
    mgr = running.host.manager
    mgr.stateless = False
    make_plugin(running.plugins_dir, "alpha", good("v1"))
    await mgr.load("alpha")
    tok = (await get_tokens(running, "alpha"))[1]
    async with mcp(running, "alpha", mode="legacy", tok=tok) as old:
        await old.list_tools()
        await mgr.reload("alpha")
        with pytest.raises(Exception):
            await old.call_tool("who", {})
    assert await say(running, "alpha", "who", tok=tok, mode="legacy") == "I am v1"


async def test_plugin_instructions_reach_the_mcp_client(running):
    src = textwrap.dedent('''
        from mcpopus.plugin import Plugin, tool
        class P(Plugin):
            def __init__(self, ctx):
                super().__init__(ctx)
                self.instructions = "Use British English. Daily notes live in Daily/."
            @tool(tier="read")
            async def t(self) -> str: return "x"
        async def setup(host): await host.add_plugin(P(host.context))
    ''')
    make_plugin(running.plugins_dir, "told", src)
    make_plugin(running.plugins_dir, "plain1", good())
    await running.host.manager.load("told")
    await running.host.manager.load("plain1")
    async with mcp(running, "told") as c:
        assert c.instructions == "Use British English. Daily notes live in Daily/."
    async with mcp(running, "plain1") as c:
        assert c.instructions == "test plugin plain1"  # without its own text, the manifest description


async def test_stateless_server_issues_no_session_id_and_accepts_a_stale_one(running):
    import httpx2

    mgr = running.host.manager
    make_plugin(running.plugins_dir, "alpha", good("v1"))
    await mgr.load("alpha")
    tok = (await get_tokens(running, "alpha"))[1]["access_token"]
    h = {"Authorization": f"Bearer {tok}", "Accept": "application/json, text/event-stream", "Content-Type": "application/json", "MCP-Protocol-Version": "2025-06-18"}
    init = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}}}
    async with httpx2.AsyncClient(base_url=running.base) as c:
        r = await c.post("/alpha/", headers=h, json=init)
        assert r.status_code == 200 and "mcp-session-id" not in r.headers
        await mgr.reload("alpha")
        r = await c.post("/alpha/", headers={**h, "Mcp-Session-Id": "0123456789abcdef0123456789abcdef"}, json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        assert r.status_code == 200 and "who" in r.text
