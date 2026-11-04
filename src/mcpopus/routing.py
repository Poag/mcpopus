"""Routing and OAuth resource binding behind one small interface.

Everything that depends on how plugin endpoints are addressed (sub-path or
subdomain) lives here: the resource URL a token is bound to, the metadata URL
in WWW-Authenticate, and how a request maps to a plugin name. Switching from
sub-paths to a subdomain per plugin is MCPOPUS_ROUTING=subdomain.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Protocol
from urllib.parse import urlsplit

NAME_RE = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
RESERVED = frozenset({"oauth", "admin", "healthz", "static", "api", "well-known", "www"})
WELL_KNOWN_PRM = "/.well-known/oauth-protected-resource"


def valid_plugin_name(name: str) -> bool:
    return bool(NAME_RE.fullmatch(name)) and name not in RESERVED


@dataclass(frozen=True)
class Route:
    plugin: str  # not yet validated
    subpath: str  # path inside the plugin endpoint, always starts with "/"


class Routing(Protocol):
    def resolve(self, host: str, path: str) -> Route | None: ...
    def metadata_plugin(self, host: str, path: str) -> str | None: ...
    def resource_url(self, plugin: str) -> str: ...
    def metadata_url(self, plugin: str) -> str: ...
    def plugin_for_resource(self, resource: str) -> str | None: ...
    def host_allowed(self, host: str) -> bool: ...


def _origin(url: str) -> tuple[str, str]:
    p = urlsplit(url)
    return p.scheme.lower(), (p.netloc or "").lower()


class PathRouting:
    """https://host/<plugin>; protected resource metadata at
    /.well-known/oauth-protected-resource/<plugin> (RFC 9728 section 3.1)."""

    def __init__(self, public_url: str) -> None:
        self.base = public_url.rstrip("/")
        self._origin = _origin(self.base)

    def resolve(self, host: str, path: str) -> Route | None:
        if not path.startswith("/") or path == "/":
            return None
        first, sep, rest = path[1:].partition("/")
        return Route(first, "/" + rest if sep else "/")

    def metadata_plugin(self, host: str, path: str) -> str | None:
        prefix = WELL_KNOWN_PRM + "/"
        if path.startswith(prefix):
            name = path[len(prefix) :]
            return name if valid_plugin_name(name) else None
        return None

    def resource_url(self, plugin: str) -> str:
        return f"{self.base}/{plugin}"

    def metadata_url(self, plugin: str) -> str:
        return f"{self.base}{WELL_KNOWN_PRM}/{plugin}"

    def plugin_for_resource(self, resource: str) -> str | None:
        p = urlsplit(resource)
        if p.query or p.fragment or _origin(resource) != self._origin:
            return None
        name = p.path.strip("/")
        return name if p.path in (f"/{name}", f"/{name}/") and valid_plugin_name(name) else None

    def host_allowed(self, host: str) -> bool:
        return host.lower() == self._origin[1]


class SubdomainRouting:
    """https://<plugin>.<domain>; metadata at /.well-known/oauth-protected-resource
    on that host. The authorization server stays on the apex host."""

    def __init__(self, public_url: str) -> None:
        self.base = public_url.rstrip("/")
        p = urlsplit(self.base)
        self.scheme = p.scheme.lower()
        self.domain = (p.hostname or "").lower()
        self.port = f":{p.port}" if p.port else ""

    def _plugin_from_host(self, host: str) -> str | None:
        hostname = host.lower().split(":")[0]
        suffix = "." + self.domain
        if hostname.endswith(suffix):
            label = hostname[: -len(suffix)]
            return label if label and "." not in label else None
        return None

    def resolve(self, host: str, path: str) -> Route | None:
        plugin = self._plugin_from_host(host)
        return Route(plugin, path or "/") if plugin else None

    def metadata_plugin(self, host: str, path: str) -> str | None:
        plugin = self._plugin_from_host(host)
        if plugin and path == WELL_KNOWN_PRM and valid_plugin_name(plugin):
            return plugin
        return None

    def resource_url(self, plugin: str) -> str:
        return f"{self.scheme}://{plugin}.{self.domain}{self.port}"

    def metadata_url(self, plugin: str) -> str:
        return self.resource_url(plugin) + WELL_KNOWN_PRM

    def plugin_for_resource(self, resource: str) -> str | None:
        p = urlsplit(resource)
        if p.query or p.fragment or p.path not in ("", "/") or p.scheme.lower() != self.scheme:
            return None
        plugin = self._plugin_from_host(p.netloc)
        if plugin and valid_plugin_name(plugin) and p.netloc.lower() == f"{plugin}.{self.domain}{self.port}":
            return plugin
        return None

    def host_allowed(self, host: str) -> bool:
        h = host.lower()
        return h == f"{self.domain}{self.port}" or self._plugin_from_host(h) is not None


def make_routing(kind: str, public_url: str) -> Routing:
    return SubdomainRouting(public_url) if kind == "subdomain" else PathRouting(public_url)
