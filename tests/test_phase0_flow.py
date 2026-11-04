from urllib.parse import parse_qs, urlsplit

from mcp import Client
from mcp.client.streamable_http import streamable_http_client

from .oauth_helpers import REDIRECT, get_tokens, pkce, register, authorize


async def test_discovery_documents(running):
    async with running.client() as c:
        as_md = (await c.get("/.well-known/oauth-authorization-server")).json()
        assert as_md["issuer"] == running.base
        assert as_md["code_challenge_methods_supported"] == ["S256"]
        assert "registration_endpoint" in as_md
        prm = (await c.get("/.well-known/oauth-protected-resource/hello")).json()
        assert prm["resource"] == f"{running.base}/hello"
        assert prm["authorization_servers"] == [running.base]


async def test_401_carries_resource_metadata(running):
    async with running.client() as c:
        r = await c.post("/hello", json={})
        assert r.status_code == 401
        assert r.headers["www-authenticate"] == f'Bearer resource_metadata="{running.base}/.well-known/oauth-protected-resource/hello"'


async def test_full_flow_and_real_mcp_client(running):
    reg, tok = await get_tokens(running)
    assert tok["token_type"] == "Bearer" and tok["refresh_token"]
    import httpx2

    http = httpx2.AsyncClient(headers={"Authorization": f"Bearer {tok['access_token']}"}, timeout=10)
    for mode in ("auto", "legacy"):
        async with Client(streamable_http_client(f"{running.base}/hello", http_client=http), mode=mode) as client:
            tools = await client.list_tools()
            assert [t.name for t in tools.tools] == ["say_hello"]
            res = await client.call_tool("say_hello", {"name": "Alex"})
            assert res.content[0].text == "Hello, Alex!"
    await http.aclose()
