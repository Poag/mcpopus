"""notes: the worked example in docs/PLUGINS.md. Two read tools, one write tool."""

from __future__ import annotations

import re
from pathlib import Path

from mcpopus.plugin import BaseModel, Field, Plugin, PluginHost, ToolError, tool

NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")


class Config(BaseModel):
    max_notes: int = Field(100, ge=1, le=10_000, description="Refuse to create more notes than this")
    max_note_bytes: int = Field(20_000, ge=100, le=1_000_000, description="Largest single note")


class Notes(Plugin):
    def _path(self, name: str) -> Path:
        if not NAME_RE.fullmatch(name):  # never build a path from unchecked input
            raise ToolError("Note names use lower-case letters, digits, '-' and '_' (max 64).")
        return self.ctx.data_dir / f"{name}.txt"

    @tool(tier="read")
    async def list_notes(self) -> list[str]:
        """List note names."""
        return sorted(p.stem for p in self.ctx.data_dir.glob("*.txt"))

    @tool(tier="read")
    async def read_note(self, name: str) -> str:
        """Read one note."""
        path = self._path(name)
        if not path.is_file():
            raise ToolError("No such note.")
        return path.read_text()

    @tool(tier="write")
    async def add_note(self, name: str, text: str) -> str:
        """Create or replace a note. Disabled until the owner enables it by name."""
        cfg = self.ctx.config
        path = self._path(name)
        if len(text.encode()) > cfg.max_note_bytes:
            raise ToolError("That note is too large.")
        if not path.exists() and len(list(self.ctx.data_dir.glob("*.txt"))) >= cfg.max_notes:
            raise ToolError("The note limit has been reached.")
        path.write_text(text)
        self.ctx.logger.info("note written (%d bytes)", len(text))
        return "saved"


async def setup(host: PluginHost) -> None:
    await host.add_plugin(Notes(host.context))
