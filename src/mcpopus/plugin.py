"""The plugin authoring API.

A plugin is a package with plugin.toml, and an __init__.py exposing:

    class Config(pydantic.BaseModel): ...        # optional config schema
    async def setup(host: PluginHost) -> None    # required
    async def teardown(host: PluginHost) -> None # optional

setup() builds a Plugin subclass instance and registers it with host.add_plugin().
Methods decorated with @tool, @resource or @prompt become the MCP surface.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

import pydantic
from mcp.server.mcpserver.exceptions import ToolError
from pydantic import BaseModel, SecretStr

if TYPE_CHECKING:
    import httpx2

__all__ = [
    "BaseModel", "Field", "Plugin", "PluginContext", "PluginHost", "SecretStr", "Tier", "ToolError",
    "prompt", "resource", "tool",
]

Field = pydantic.Field
Tier = Literal["read", "write", "admin"]
TIERS = ("read", "write", "admin")
MARK = "__mcpopus__"


@dataclass(frozen=True)
class Meta:
    kind: Literal["tool", "resource", "prompt"]
    name: str
    tier: Tier = "read"
    untrusted: bool = False
    description: str | None = None
    uri: str | None = None


def tool(*, tier: Tier = "read", name: str | None = None, description: str | None = None, untrusted: bool = False) -> Callable:
    """Declare a tool. Every tool states its tier. Set untrusted=True when the
    result comes from outside (mail, web): the host marks and size-caps it."""
    if tier not in TIERS:
        raise ValueError(f"tier must be one of {TIERS}")

    def deco(fn: Callable) -> Callable:
        setattr(fn, MARK, Meta("tool", name or fn.__name__, tier, untrusted, description))
        return fn

    return deco


def resource(uri: str, *, name: str | None = None, description: str | None = None, untrusted: bool = False) -> Callable:
    def deco(fn: Callable) -> Callable:
        setattr(fn, MARK, Meta("resource", name or fn.__name__, "read", untrusted, description, uri))
        return fn

    return deco


def prompt(*, name: str | None = None, description: str | None = None) -> Callable:
    def deco(fn: Callable) -> Callable:
        setattr(fn, MARK, Meta("prompt", name or fn.__name__, "read", False, description))
        return fn

    return deco


AuditHook = Callable[..., None]


@dataclass(frozen=True)
class PluginContext:
    """Everything a plugin is given. Nothing else is handed over."""

    name: str
    config: Any  # the validated Config instance, or None if the plugin has no Config
    data_dir: Path
    logger: logging.Logger
    http: httpx2.AsyncClient
    audit: AuditHook


class Plugin:
    """Base class (the cog analogue). Subclass it and decorate methods."""

    def __init__(self, ctx: PluginContext) -> None:
        self.ctx = ctx


@dataclass
class PluginHost:
    """The object passed to setup() and teardown()."""

    context: PluginContext
    _registered: list[Plugin] = field(default_factory=list)

    async def add_plugin(self, plugin: Plugin) -> None:
        if not isinstance(plugin, Plugin):
            raise TypeError("add_plugin() needs a mcpopus.plugin.Plugin instance")
        if self._registered:
            raise RuntimeError("a plugin package registers exactly one Plugin object")
        self._registered.append(plugin)


SetupFn = Callable[[PluginHost], Awaitable[None]]
