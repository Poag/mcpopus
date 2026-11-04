"""hello: the smallest useful plugin. See docs/PLUGINS.md for a walk-through."""

from __future__ import annotations

from mcpopus.plugin import BaseModel, Field, Plugin, PluginHost, tool


class Config(BaseModel):
    greeting: str = Field("Hello", max_length=40, description="Word used to greet people")


class Hello(Plugin):
    @tool(tier="read")
    async def say_hello(self, name: str = "world") -> str:
        """Greet someone by name."""
        return f"{self.ctx.config.greeting}, {name[:100]}!"


async def setup(host: PluginHost) -> None:
    await host.add_plugin(Hello(host.context))
