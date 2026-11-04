from __future__ import annotations

import base64
import hashlib
import re
import secrets
from urllib.parse import parse_qs, urlsplit

import httpx2

from .conftest import PASSWORD, Running

REDIRECT = "https://claude.ai/api/mcp/auth_callback"


def pkce() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    return verifier, challenge


async def register(c: httpx2.AsyncClient, redirect=REDIRECT, **extra) -> dict:
    r = await c.post("/oauth/register", json={"redirect_uris": [redirect], "client_name": "Test client", **extra})
    assert r.status_code == 201, r.text
    return r.json()


def form_fields(html: str) -> dict[str, str]:
    return dict(re.findall(r'name="(request_id|csrf)" value="([^"]+)"', html))


async def authorize(run: Running, c: httpx2.AsyncClient, client_id: str, challenge: str, resource: str | None,
                    redirect=REDIRECT, state="xyz", password=PASSWORD, totp=None, decision="approve", extra=None):
    params = {"response_type": "code", "client_id": client_id, "redirect_uri": redirect, "code_challenge": challenge,
              "code_challenge_method": "S256", "state": state, **(extra or {})}
    if resource:
        params["resource"] = resource
    r = await c.get("/oauth/authorize", params=params)
    if r.status_code != 200:
        return r
    fields = form_fields(r.text)
    return await c.post("/oauth/authorize", data={**fields, "password": password, "totp": totp or run.totp(), "decision": decision})


async def get_tokens(run: Running, plugin: str = "hello", c: httpx2.AsyncClient | None = None):
    own = c is None
    c = c or run.client()
    try:
        reg = await register(c)
        verifier, challenge = pkce()
        resource = f"{run.base}/{plugin}"
        r = await authorize(run, c, reg["client_id"], challenge, resource)
        assert r.status_code == 303, r.text
        q = parse_qs(urlsplit(r.headers["location"]).query)
        t = await c.post("/oauth/token", data={"grant_type": "authorization_code", "code": q["code"][0], "redirect_uri": REDIRECT,
                                               "code_verifier": verifier, "client_id": reg["client_id"]})
        assert t.status_code == 200, t.text
        return reg, t.json()
    finally:
        if own:
            await c.aclose()


from contextlib import asynccontextmanager

from mcp import Client
from mcp.client.streamable_http import streamable_http_client


@asynccontextmanager
async def mcp(running: Running, plugin: str = "hello", mode: str = "auto", tok: dict | None = None):
    tok = tok or (await get_tokens(running, plugin))[1]
    http = httpx2.AsyncClient(headers={"Authorization": f"Bearer {tok['access_token']}"}, timeout=10)
    try:
        async with Client(streamable_http_client(f"{running.base}/{plugin}", http_client=http), mode=mode) as c:
            yield c
    finally:
        await http.aclose()


async def say(running: Running, plugin: str, tool: str, args: dict | None = None, tok: dict | None = None, mode: str = "auto") -> str:
    async with mcp(running, plugin, mode, tok) as c:
        res = await c.call_tool(tool, args or {})
        return res.content[0].text
