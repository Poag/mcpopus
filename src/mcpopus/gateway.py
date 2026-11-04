"""The dispatcher: one catch-all route that finds the plugin in the registry.

Order of checks for a request to /<plugin>:
  1. Host allow-list (421 otherwise).
  2. Protected resource metadata paths are answered here (RFC 9728).
  3. Plugin name syntax (404 for names that cannot be plugins, e.g. traversal).
  4. Bearer token bound to this plugin's resource. Missing token, bad token, a token
     for another plugin and an unknown plugin all give the same 401.
  5. Only then is the registry consulted and the request handed to the plugin's app.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from starlette.types import Receive, Scope, Send

from .context import current_client
from .manager import PluginManager
from .oauth import OAuthServer
from .routing import Routing, valid_plugin_name


async def _respond(send: Send, status: int, body: dict, headers: list[tuple[bytes, bytes]] | None = None) -> None:
    payload = json.dumps(body).encode()
    hdrs = [(b"content-type", b"application/json"), (b"content-length", str(len(payload)).encode()),
            (b"cache-control", b"no-store"), (b"x-content-type-options", b"nosniff")]
    await send({"type": "http.response.start", "status": status, "headers": hdrs + (headers or [])})
    await send({"type": "http.response.body", "body": payload})


def _header(scope: Scope, name: bytes) -> str:
    for k, v in scope["headers"]:
        if k == name:
            return v.decode("latin-1")
    return ""


log = logging.getLogger("mcpopus.gateway")


class Gateway:
    def __init__(self, routing: Routing, oauth: OAuthServer, manager: PluginManager) -> None:
        self.routing, self.oauth, self.manager = routing, oauth, manager

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            return
        host, path = _header(scope, b"host"), scope["path"]
        if not self.routing.host_allowed(host):
            await _respond(send, 421, {"error": "misdirected_request"})
            return

        meta_plugin = self.routing.metadata_plugin(host, path)
        if meta_plugin is not None:
            log.debug("metadata request for %s ua=%r", meta_plugin, _header(scope, b"user-agent")[:100])
            await _respond(send, 200, self.oauth.prm(meta_plugin))
            return

        route = self.routing.resolve(host, path)
        if route is None or not valid_plugin_name(route.plugin):
            await _respond(send, 404, {"error": "not_found"})
            return

        resource = self.routing.resource_url(route.plugin)
        principal = None
        auth = _header(scope, b"authorization")
        if auth[:7].lower() == "bearer " and len(auth) < 512:
            principal = self.oauth.verify_access_token(auth[7:].strip(), resource)
        loaded = self.manager.get(route.plugin) if principal else None
        if principal is None:
            # Identical for: no token, bad token, token for another plugin, unknown plugin.
            log.debug("401 %s %r token_presented=%s ua=%r", scope["method"], path[:64], bool(auth), _header(scope, b"user-agent")[:100])
            challenge = f'Bearer resource_metadata="{self.routing.metadata_url(route.plugin)}"'
            await _respond(send, 401, {"error": "unauthorized"}, [(b"www-authenticate", challenge.encode())])
            return
        if loaded is None:
            await _respond(send, 503, {"error": "plugin_unavailable"}, [(b"retry-after", b"5")])
            return
        if route.subpath != "/":
            await _respond(send, 404, {"error": "not_found"})
            return

        inner: dict[str, Any] = dict(scope, path="/", raw_path=b"/", root_path="")
        token = current_client.set(principal.client_id)
        loaded.inflight += 1
        try:
            await loaded.app(inner, receive, send)
        finally:
            loaded.inflight -= 1
            current_client.reset(token)
