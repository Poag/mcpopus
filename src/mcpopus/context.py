"""Per-request context shared between the gateway and tool wrappers."""

from contextvars import ContextVar

current_client: ContextVar[str | None] = ContextVar("mcpopus_current_client", default=None)
