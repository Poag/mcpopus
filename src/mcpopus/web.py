"""Shared web helpers: security headers, templates, capped body reading, client IP."""

from __future__ import annotations

from typing import Any

import time

from jinja2 import Environment, PackageLoader, select_autoescape
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, Response

env = Environment(
    loader=PackageLoader("mcpopus", "templates"),
    autoescape=select_autoescape(["html"]),  # autoescape on: all variables are HTML-escaped
)

from .stats import ago, human_bytes  # noqa: E402

env.filters["bytes"] = human_bytes
env.filters["ago"] = ago
env.filters["utc"] = lambda ts: time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(ts)) if ts else "never"

SECURITY_HEADERS = {
    "Cache-Control": "no-store",
    "Pragma": "no-cache",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": "default-src 'none'; img-src data:; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'",
}

MAX_FORM_BYTES = 16 * 1024


def html_page(template: str, status: int = 200, **ctx: Any) -> HTMLResponse:
    return HTMLResponse(env.get_template(template).render(**ctx), status_code=status, headers=SECURITY_HEADERS)


def json_response(data: Any, status: int = 200, headers: dict[str, str] | None = None) -> JSONResponse:
    h = {"Cache-Control": "no-store", "Pragma": "no-cache", "X-Content-Type-Options": "nosniff"}
    h.update(headers or {})
    return JSONResponse(data, status_code=status, headers=h)


class BodyTooLarge(Exception):
    pass


async def read_body(request: Request, limit: int = MAX_FORM_BYTES) -> bytes:
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > limit:
        raise BodyTooLarge
    chunks, total = [], 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > limit:
            raise BodyTooLarge
        chunks.append(chunk)
    return b"".join(chunks)


async def read_form(request: Request) -> dict[str, str]:
    """Parse an application/x-www-form-urlencoded body with a size cap.
    Repeated keys are kept as lists only via read_form_multi."""
    from urllib.parse import parse_qsl

    body = await read_body(request)
    return dict(parse_qsl(body.decode("utf-8", "replace"), keep_blank_values=True))


async def read_form_multi(request: Request) -> list[tuple[str, str]]:
    from urllib.parse import parse_qsl

    return parse_qsl((await read_body(request)).decode("utf-8", "replace"), keep_blank_values=True)


def client_ip(request: Request, trust_proxy_headers: bool) -> str:
    """Peer address, or the first X-Forwarded-For / CF-Connecting-IP entry when
    the operator has said the listener is reachable only through a trusted proxy."""
    if trust_proxy_headers:
        for h in ("cf-connecting-ip", "x-forwarded-for"):
            v = request.headers.get(h)
            if v:
                return v.split(",")[0].strip()[:64]
    return request.client.host if request.client else "unknown"


def plain(status: int, text: str, headers: dict[str, str] | None = None) -> Response:
    return Response(text, status_code=status, media_type="text/plain", headers=headers)
