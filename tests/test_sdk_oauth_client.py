"""Drive the flow with the MCP SDK's own OAuth client (discovery, registration, PKCE, refresh)."""

from urllib.parse import parse_qs, urlsplit

import httpx2
from mcp import Client
from mcp.client.auth import AuthorizationCodeResult, OAuthClientProvider
from mcp.client.streamable_http import streamable_http_client
from mcp.shared.auth import OAuthClientMetadata
from pydantic import AnyUrl

from .oauth_helpers import form_fields
from .conftest import PASSWORD


class Storage:
    def __init__(self):
        self.tokens = self.client_info = None

    async def get_tokens(self): return self.tokens
    async def set_tokens(self, t): self.tokens = t
    async def get_client_info(self): return self.client_info
    async def set_client_info(self, c): self.client_info = c


async def test_sdk_oauth_client_end_to_end(running):
    seen = {}
    storage = Storage()
    browser = running.client()

    async def redirect_handler(url: str) -> None:
        seen["authorize_url"] = url
        r = await browser.get(url)
        assert r.status_code == 200, r.text
        r = await browser.post("/oauth/authorize", data={**form_fields(r.text), "password": PASSWORD, "totp": running.totp(), "decision": "approve"})
        assert r.status_code == 303, r.text
        seen["callback"] = r.headers["location"]

    async def callback_handler() -> AuthorizationCodeResult:
        q = parse_qs(urlsplit(seen["callback"]).query)
        return AuthorizationCodeResult(code=q["code"][0], state=q["state"][0], iss=q.get("iss", [None])[0])

    oauth = OAuthClientProvider(
        server_url=f"{running.base}/hello",
        client_metadata=OAuthClientMetadata(client_name="SDK test", redirect_uris=[AnyUrl("http://localhost:3030/callback")], scope="mcp"),
        storage=storage, redirect_handler=redirect_handler, callback_handler=callback_handler,
    )
    async with httpx2.AsyncClient(auth=oauth, timeout=httpx2.Timeout(30.0, read=300.0)) as http:
        async with Client(streamable_http_client(f"{running.base}/hello", http_client=http)) as client:
            res = await client.call_tool("say_hello", {"name": "SDK"})
            assert res.content[0].text == "Hello, SDK!"
    q = parse_qs(urlsplit(seen["authorize_url"]).query)
    assert q["resource"] == [f"{running.base}/hello"]  # the SDK client sends an RFC 8707 resource
    assert q["code_challenge_method"] == ["S256"]
    assert storage.tokens.refresh_token
    await browser.aclose()
