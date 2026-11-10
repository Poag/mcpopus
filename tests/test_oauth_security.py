import re
from urllib.parse import parse_qs, urlsplit

import pytest

from .conftest import make_plugin, PASSWORD
from .oauth_helpers import REDIRECT, authorize, form_fields, get_tokens, pkce, register

OTHER = '''
from mcpopus.plugin import Plugin, tool

class P(Plugin):
    @tool(tier="read")
    async def ping(self) -> str:
        return "pong"

async def setup(host):
    await host.add_plugin(P(host.context))
'''


def norm(resp, name):
    return (resp.status_code, resp.text, resp.headers.get("www-authenticate", "").replace(name, "NAME"), resp.headers.get("content-type"))


async def code_for(run, c, plugin="hello", **kw):
    reg = await register(c)
    verifier, challenge = pkce()
    r = await authorize(run, c, reg["client_id"], challenge, f"{run.base}/{plugin}", **kw)
    return reg, verifier, challenge, r


async def test_token_for_plugin_a_is_rejected_on_plugin_b(running):
    make_plugin(running.plugins_dir, "other", OTHER)
    await running.host.manager.load("other")
    reg, tok = await get_tokens(running, "hello")
    async with running.client() as c:
        h = {"Authorization": f"Bearer {tok['access_token']}"}
        ok = await c.post("/hello", headers=h, json={})
        assert ok.status_code != 401  # accepted by hello (the body is not valid MCP, which is irrelevant here)
        bad = await c.post("/other", headers=h, json={})
        assert bad.status_code == 401
        ghost = await c.post("/ghost", headers=h, json={})
        nothing = await c.post("/other", json={})
        junk = await c.post("/other", headers={"Authorization": "Bearer at_nonsense"}, json={})
        assert norm(bad, "other") == norm(ghost, "ghost") == norm(nothing, "other") == norm(junk, "other")
        assert "resource_metadata" in bad.headers["www-authenticate"]


async def test_cannot_obtain_token_for_unknown_or_missing_resource(running):
    async with running.client() as c:
        for resource in (f"{running.base}/ghost", None, "https://evil.example/hello", f"{running.base}/hello/../x"):
            reg = await register(c)
            _, ch = pkce()
            r = await authorize(running, c, reg["client_id"], ch, resource)
            assert r.status_code == 303
            q = parse_qs(urlsplit(r.headers["location"]).query)
            assert q["error"] == ["invalid_target"], resource
            assert q["iss"] == [running.base] and q["state"] == ["xyz"]


async def test_two_resources_rejected(running):
    async with running.client() as c:
        reg = await register(c)
        _, ch = pkce()
        r = await c.get("/oauth/authorize", params=[("response_type", "code"), ("client_id", reg["client_id"]), ("redirect_uri", REDIRECT), ("code_challenge", ch), ("code_challenge_method", "S256"), ("resource", f"{running.base}/hello"), ("resource", f"{running.base}/hello")])
        assert parse_qs(urlsplit(r.headers["location"]).query)["error"] == ["invalid_target"]


async def test_pkce_plain_is_refused_and_s256_required(running):
    async with running.client() as c:
        reg = await register(c)
        r = await c.get("/oauth/authorize", params={"response_type": "code", "client_id": reg["client_id"], "redirect_uri": REDIRECT, "code_challenge": "x" * 43, "code_challenge_method": "plain", "resource": f"{running.base}/hello"})
        assert parse_qs(urlsplit(r.headers["location"]).query)["error"] == ["invalid_request"]
        r = await c.get("/oauth/authorize", params={"response_type": "code", "client_id": reg["client_id"], "redirect_uri": REDIRECT, "resource": f"{running.base}/hello"})
        assert parse_qs(urlsplit(r.headers["location"]).query)["error"] == ["invalid_request"]


async def test_wrong_verifier_and_code_reuse(running):
    async with running.client() as c:
        reg, verifier, _, r = await code_for(running, c)
        code = parse_qs(urlsplit(r.headers["location"]).query)["code"][0]
        base = {"grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT, "client_id": reg["client_id"]}
        bad = await c.post("/oauth/token", data={**base, "code_verifier": "A" * 43})
        assert bad.status_code == 400 and bad.json()["error"] == "invalid_grant"
        # the failed attempt consumed the code: the right verifier no longer works
        again = await c.post("/oauth/token", data={**base, "code_verifier": verifier})
        assert again.json()["error"] == "invalid_grant"


async def test_code_replay_revokes_issued_tokens(running):
    async with running.client() as c:
        reg, verifier, _, r = await code_for(running, c)
        code = parse_qs(urlsplit(r.headers["location"]).query)["code"][0]
        data = {"grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT, "client_id": reg["client_id"], "code_verifier": verifier}
        first = await c.post("/oauth/token", data=data)
        assert first.status_code == 200
        replay = await c.post("/oauth/token", data=data)
        assert replay.json()["error"] == "invalid_grant"
        r = await c.post("/hello", headers={"Authorization": f"Bearer {first.json()['access_token']}"}, json={})
        assert r.status_code == 401


async def test_redirect_uri_must_match_and_is_not_followed(running):
    async with running.client() as c:
        reg = await register(c)
        _, ch = pkce()
        r = await c.get("/oauth/authorize", params={"response_type": "code", "client_id": reg["client_id"], "redirect_uri": "https://evil.example/cb", "code_challenge": ch, "code_challenge_method": "S256", "resource": f"{running.base}/hello"})
        assert r.status_code == 400 and "location" not in r.headers


async def test_dcr_rejects_unlisted_redirects(running):
    async with running.client() as c:
        for uri in ("https://evil.example/cb", "http://evil.example/cb", "javascript:alert(1)", "https://claude.ai/api/mcp/auth_callback#x"):
            r = await c.post("/oauth/register", json={"redirect_uris": [uri]})
            assert r.status_code == 400 and r.json()["error"] == "invalid_redirect_uri", uri
        ok = await c.post("/oauth/register", json={"redirect_uris": ["http://localhost:5555/callback"]})
        assert ok.status_code == 201


async def test_refresh_rotation_and_reuse_detection(running):
    reg, tok = await get_tokens(running)
    async with running.client() as c:
        data = {"grant_type": "refresh_token", "client_id": reg["client_id"]}
        r1 = await c.post("/oauth/token", data={**data, "refresh_token": tok["refresh_token"]})
        assert r1.status_code == 200 and r1.json()["refresh_token"] != tok["refresh_token"]
        stale = await c.post("/oauth/token", data={**data, "refresh_token": tok["refresh_token"]})
        assert stale.status_code == 400 and stale.json()["error"] == "invalid_grant"
        # reuse of a rotated token revoked the whole grant, including the newest tokens
        r3 = await c.post("/oauth/token", data={**data, "refresh_token": r1.json()["refresh_token"]})
        assert r3.json()["error"] == "invalid_grant"
        r = await c.post("/hello", headers={"Authorization": f"Bearer {r1.json()['access_token']}"}, json={})
        assert r.status_code == 401


async def test_expired_access_token_rejected(running):
    _, tok = await get_tokens(running)
    running.host.store._run("UPDATE tokens SET expires_at=0 WHERE kind='access'")
    async with running.client() as c:
        r = await c.post("/hello", headers={"Authorization": f"Bearer {tok['access_token']}"}, json={})
        assert r.status_code == 401


async def test_client_revocation_kills_tokens(running):
    reg, tok = await get_tokens(running)
    running.host.store.revoke_client(reg["client_id"])
    async with running.client() as c:
        r = await c.post("/hello", headers={"Authorization": f"Bearer {tok['access_token']}"}, json={})
        assert r.status_code == 401


async def test_token_endpoint_requires_form_encoding(running):
    async with running.client() as c:
        r = await c.post("/oauth/token", json={"grant_type": "refresh_token"})
        assert r.status_code == 415


async def test_revocation_endpoint(running):
    reg, tok = await get_tokens(running)
    async with running.client() as c:
        r = await c.post("/oauth/revoke", data={"token": tok["refresh_token"], "client_id": reg["client_id"]})
        assert r.status_code == 200
        r = await c.post("/hello", headers={"Authorization": f"Bearer {tok['access_token']}"}, json={})
        assert r.status_code == 401


async def test_confidential_client_needs_secret(running):
    async with running.client() as c:
        reg = await register(c, token_endpoint_auth_method="client_secret_post")
        assert reg["client_secret"]
        verifier, ch = pkce()
        r = await authorize(running, c, reg["client_id"], ch, f"{running.base}/hello")
        code = parse_qs(urlsplit(r.headers["location"]).query)["code"][0]
        data = {"grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT, "client_id": reg["client_id"], "code_verifier": verifier}
        assert (await c.post("/oauth/token", data=data)).status_code == 401
        assert (await c.post("/oauth/token", data={**data, "client_secret": "wrong"})).status_code == 401


async def test_bad_password_and_bad_totp_look_the_same_and_are_rate_limited(running):
    async with running.client() as c:
        reg = await register(c)
        _, ch = pkce()
        outcomes = []
        # one authorisation request allows 5 attempts; use fresh requests to hit the per-IP limit
        for i in range(5):
            r = await authorize(running, c, reg["client_id"], ch, f"{running.base}/hello", password="wrong-password-123" if i % 2 else PASSWORD, totp="000000")
            outcomes.append((r.status_code, re.sub(r'value="[^"]+"', "", r.text)))
        assert {o[0] for o in outcomes} == {401}
        assert len({o[1] for o in outcomes}) == 1  # identical page whichever factor was wrong
        # sixth attempt, even with the right credentials, is refused by the limiter
        r = await authorize(running, c, reg["client_id"], ch, f"{running.base}/hello")
        assert r.status_code == 429


async def test_totp_code_cannot_be_replayed(running):
    async with running.client() as c:
        code = running.totp()
        reg = await register(c)
        _, ch = pkce()
        r1 = await authorize(running, c, reg["client_id"], ch, f"{running.base}/hello", totp=code)
        assert r1.status_code == 303
        r2 = await authorize(running, c, reg["client_id"], ch, f"{running.base}/hello", totp=code)
        assert r2.status_code == 401


async def test_deny_returns_access_denied_without_credentials(running):
    async with running.client() as c:
        reg = await register(c)
        _, ch = pkce()
        r = await authorize(running, c, reg["client_id"], ch, f"{running.base}/hello", decision="deny", password="", totp="")
        assert parse_qs(urlsplit(r.headers["location"]).query)["error"] == ["access_denied"]


async def test_authorize_page_names_plugin_and_has_security_headers(running):
    async with running.client() as c:
        reg = await register(c)
        _, ch = pkce()
        r = await c.get("/oauth/authorize", params={"response_type": "code", "client_id": reg["client_id"], "redirect_uri": REDIRECT, "code_challenge": ch, "code_challenge_method": "S256", "resource": f"{running.base}/hello"})
        assert "<strong>hello</strong>" in r.text and "claude.ai" in r.text
        assert r.headers["x-frame-options"] == "DENY" and "frame-ancestors 'none'" in r.headers["content-security-policy"]


async def test_client_name_is_escaped(running):
    async with running.client() as c:
        r = await c.post("/oauth/register", json={"redirect_uris": [REDIRECT], "client_name": "<script>alert(1)</script>"})
        reg = r.json()
        _, ch = pkce()
        page = await c.get("/oauth/authorize", params={"response_type": "code", "client_id": reg["client_id"], "redirect_uri": REDIRECT, "code_challenge": ch, "code_challenge_method": "S256", "resource": f"{running.base}/hello"})
        assert "<script>alert" not in page.text


@pytest.mark.parametrize("path", ["/..%2f..%2fetc%2fpasswd", "/%2e%2e/secret", "/Hello", "/hello%00", "/he llo", "/oauth", "/admin", "/-x", "/" + "a" * 40])
async def test_plugin_names_cannot_traverse_or_collide(running, path):
    async with running.client() as c:
        r = await c.post(path, json={})
        assert r.status_code in (404, 401, 400)
        if r.status_code == 401:
            assert "resource_metadata" in r.headers["www-authenticate"]


async def test_unsyntactic_names_do_not_get_metadata(running):
    async with running.client() as c:
        for name in ("..", "%2e%2e", "Hello", "a/b", "oauth"):
            r = await c.get(f"/.well-known/oauth-protected-resource/{name}")
            assert r.status_code in (404, 200) and (r.status_code == 404 or "resource" in r.json())
            if r.status_code == 200:
                assert r.json()["resource"].count("/") == 3  # no path smuggling in the resource URL


async def test_wrong_host_header_is_refused(running):
    async with running.client() as c:
        r = await c.post("/hello", headers={"Host": "evil.example"}, json={})
        assert r.status_code == 421


async def test_dcr_is_rate_limited(running):
    async with running.client() as c:
        codes = [(await c.post("/oauth/register", json={"redirect_uris": [REDIRECT]})).status_code for _ in range(12)]
        assert codes[:10] == [201] * 10 and 429 in codes[10:]


async def test_oversized_bodies_rejected(running):
    async with running.client() as c:
        r = await c.post("/oauth/register", content=b"{" + b" " * 20000 + b"}", headers={"content-type": "application/json"})
        assert r.status_code == 400
        r = await c.post("/oauth/token", content=b"a=" + b"x" * 20000, headers={"content-type": "application/x-www-form-urlencoded"})
        assert r.status_code in (400, 413)


async def test_failed_login_logs_the_reason_but_not_the_secrets(running, caplog):
    import logging

    from mcpopus import credentials

    caplog.set_level(logging.WARNING, logger="mcpopus.oauth")
    async with running.client() as c:
        reg = await register(c)
        _, ch = pkce()
        await authorize(running, c, reg["client_id"], ch, f"{running.base}/hello", password="a wrong password 123", totp="000000")
        await authorize(running, c, reg["client_id"], ch, f"{running.base}/hello", totp="000000")
        running.host.store.set_credential("oauth", credentials.hash_password(PASSWORD), "")
        await authorize(running, c, reg["client_id"], ch, f"{running.base}/hello", totp="000000")
    text = caplog.text
    assert ": password" in text and ": authenticator code" in text and "authenticator is not set up" in text
    assert "a wrong password 123" not in text and PASSWORD not in text

