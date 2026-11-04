import shutil

from mcpopus.pluginconfig import Policy

from .conftest import ROOT
from .oauth_helpers import mcp


async def test_notes_example_follows_the_documented_behaviour(running):
    shutil.copytree(ROOT / "plugins" / "notes", running.plugins_dir / "notes")
    await running.host.manager.load("notes")
    async with mcp(running, "notes") as c:
        assert sorted(t.name for t in (await c.list_tools()).tools) == ["list_notes", "read_note"]  # read-only by default
    running.host.configs.save("notes", policy=Policy(read_only=False, enable_tools=["add_note"]))
    await running.host.manager.reload("notes")
    async with mcp(running, "notes") as c:
        assert (await c.call_tool("add_note", {"name": "todo", "text": "milk"})).content[0].text == "saved"
        assert "todo" in (await c.call_tool("list_notes", {})).content[0].text
        assert (await c.call_tool("read_note", {"name": "todo"})).content[0].text == "milk"
        for bad in ("../../etc/passwd", "a/b", "..", "UP", "x" * 70):
            r = await c.call_tool("read_note", {"name": bad})
            assert r.is_error
        assert not list(running.settings.data_dir.parent.glob("**/passwd"))
