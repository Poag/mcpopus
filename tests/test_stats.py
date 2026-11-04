"""Usage statistics: per plugin, tool and client; plugin counters; privacy; the admin pages."""

import textwrap

from mcpopus.pluginconfig import Policy

from .conftest import make_plugin
from .oauth_helpers import mcp

SRC = textwrap.dedent('''
    from mcpopus.plugin import Plugin, ToolError, tool

    class P(Plugin):
        @tool(tier="read")
        async def peek(self, q: str = "") -> str:
            return "peeked " + q

        @tool(tier="read")
        async def boom(self) -> str:
            raise ToolError("nope")

        @tool(tier="read")
        async def save(self, n: int) -> str:
            self.ctx.stats.count("bytes_written", n)
            self.ctx.stats.count("Bad Name", 5)
            return "ok"

    async def setup(host):
        await host.add_plugin(P(host.context))
''')


async def test_calls_errors_bytes_and_counters_are_recorded(running):
    make_plugin(running.plugins_dir, "st", SRC)
    running.host.configs.save("st", policy=Policy(rate_limit_per_minute=0))
    await running.host.manager.load("st")
    async with mcp(running, "st") as c:
        await c.call_tool("peek", {"q": "hello-secret-argument"})
        await c.call_tool("peek", {})
        await c.call_tool("boom", {})
        await c.call_tool("save", {"n": 1500})
        await c.call_tool("save", {"n": 500})
    s = running.host.stats
    t = s.totals(1, plugin="st")
    assert t["calls"] == 5 and t["errors"] == 1 and t["bytes_out"] > 0 and t["bytes_in"] > 0
    tools = {r["tool"]: r for r in s.by_tool("st")}
    assert tools["peek"]["calls"] == 2 and tools["boom"]["errors"] == 1
    assert s.counters("st") == {"bytes_written": 2000.0}  # the badly named counter is ignored
    assert len(s.by_client()) == 1 and next(iter(s.by_client().values()))["calls"] == 5
    assert len(s.per_day("st", 14)) == 14 and s.per_day("st", 14)[-1]["calls"] == 5
    # privacy: the argument value is nowhere in the database
    dump = "\n".join(str(tuple(r)) for tbl in ("usage", "counters") for r in running.host.store._all(f"SELECT * FROM {tbl}"))
    assert "hello-secret-argument" not in dump


def test_counter_limits(running):
    s = running.host.stats
    for i in range(30):
        s.count("p", f"c{i}", 1)
    assert len(s.counters("p")) == 20
    s.count("p", "c0", -5)
    s.count("p", "c0", float("nan"))
    assert s.counters("p")["c0"] == 1.0


async def test_stats_show_in_the_admin_pages(running):
    make_plugin(running.plugins_dir, "st", SRC)
    running.host.configs.save("st", policy=Policy(rate_limit_per_minute=0))
    await running.host.manager.load("st")
    async with mcp(running, "st") as c:
        await c.call_tool("save", {"n": 2048})
    async with running.admin() as (a, _):
        assert "calls today" in (await a.get("/")).text
        page = (await a.get("/plugins/st")).text
        assert "Usage" in page and "bytes_written" in page and "2.0 KB" in page
        assert "Calls (30 days)" in (await a.get("/access")).text
