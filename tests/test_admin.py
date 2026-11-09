import json
import re
import textwrap

import httpx2

from .conftest import ADMIN_PASSWORD, make_plugin
from .oauth_helpers import get_tokens, mcp, say

IMAPISH = textwrap.dedent('''
    from mcpopus.plugin import BaseModel, Field, Plugin, SecretStr, tool

    class Config(BaseModel):
        host: str = Field(description="Server name")
        port: int = 993
        use_tls: bool = True
        folders: list[str] = ["INBOX"]
        password: SecretStr

    class P(Plugin):
        @tool(tier="read")
        async def info(self) -> str:
            c = self.ctx.config
            return f"{c.host}:{c.port} tls={c.use_tls} folders={','.join(c.folders)} pw_len={len(c.password.get_secret_value())}"

        @tool(tier="write")
        async def mutate(self) -> str:
            return "done"

    async def setup(host):
        await host.add_plugin(P(host.context))
''')


async def test_admin_requires_login_and_has_own_credentials(running):
    async with httpx2.AsyncClient(base_url=running.admin_base, follow_redirects=False) as c:
        for path in ("/", "/access", "/audit", "/plugins/hello"):
            r = await c.get(path)
            assert r.status_code == 303 and r.headers["location"] == "/login"
        # the OAuth password does not work on the admin login
        from .conftest import PASSWORD

        r = await c.post("/login", data={"password": PASSWORD, "totp": running.admin_totp()})
        assert r.status_code == 401
        r = await c.post("/login", data={"password": ADMIN_PASSWORD, "totp": "000000"})
        assert r.status_code == 401


async def test_admin_is_not_served_on_the_public_listener(running):
    async with running.client() as c:
        for p in ("/admin", "/login", "/access", "/audit"):
            r = await c.get(p)
            assert r.status_code in (404, 401)
            assert "mcpopus admin" not in r.text


async def test_admin_login_rate_limit(running):
    async with httpx2.AsyncClient(base_url=running.admin_base, follow_redirects=False) as c:
        codes = [(await c.post("/login", data={"password": "wrong-password-xx", "totp": "000000"})).status_code for _ in range(5)]
        assert codes == [401] * 5
        r = await c.post("/login", data={"password": ADMIN_PASSWORD, "totp": running.admin_totp()})
        assert r.status_code == 429


async def test_session_cookie_flags_and_csrf(running):
    async with httpx2.AsyncClient(base_url=running.admin_base, follow_redirects=False) as raw:
        r = await raw.post("/login", data={"password": ADMIN_PASSWORD, "totp": running.admin_totp()})
        cookie = r.headers["set-cookie"].lower()
        assert "httponly" in cookie and "samesite=strict" in cookie
    async with running.admin() as (c, csrf):
        # POST without or with a wrong token is refused and changes nothing
        for data in ({"action": "unload"}, {"action": "unload", "csrf": "wrong"}):
            r = await c.post("/plugins/hello/action", data=data)
            assert r.status_code == 403
        assert running.host.manager.is_loaded("hello")
        # GET never changes state
        await c.get("/plugins/hello/action")
        assert running.host.manager.is_loaded("hello")
        r = await c.post("/plugins/hello/action", data={"action": "unload", "csrf": csrf})
        assert r.status_code == 303 and not running.host.manager.is_loaded("hello")


async def test_logout_invalidates_session(running):
    async with running.admin() as (c, csrf):
        sid = c.cookies.get("mcpopus_admin")
        await c.post("/logout", data={"csrf": csrf})
        c.cookies.set("mcpopus_admin", sid)
        assert (await c.get("/")).status_code == 303


async def test_host_header_allowlist_blocks_rebinding(running):
    async with running.admin() as (c, _):
        assert (await c.get("/", headers={"Host": "evil.example"})).status_code == 421
        assert (await c.get("/", headers={"Host": "localhost:8081"})).status_code == 200


async def test_plugin_control_from_the_ui(running):
    make_plugin(running.plugins_dir, "alpha", IMAPISH.replace("password: SecretStr", "password: SecretStr = SecretStr('pw-default')").replace("host: str = Field(description=\"Server name\")", "host: str = 'h'"))
    async with running.admin() as (c, csrf):
        page = await c.get("/")
        assert "alpha" in page.text and "hello" in page.text
        for action, check in (("load", True), ("reload", True), ("unload", False)):
            await c.post("/plugins/alpha/action", data={"action": action, "csrf": csrf})
            assert running.host.manager.is_loaded("alpha") is check
        r = await c.post("/plugins/alpha/action", data={"action": "rm -rf", "csrf": csrf})
        assert r.status_code == 404
        r = await c.post("/plugins/..%2f/action", data={"action": "load", "csrf": csrf})
        assert r.status_code == 404


async def test_config_form_secrets_validation_and_reload(running):
    make_plugin(running.plugins_dir, "mail", IMAPISH)
    async with running.admin() as (c, csrf):
        await c.post("/plugins/mail/action", data={"action": "load", "csrf": csrf})
        assert not running.host.manager.is_loaded("mail")  # required settings missing: not loaded
        page = await c.get("/plugins/mail")
        assert 'name="f_host"' in page.text and 'type="password"' in page.text and "Server name" in page.text
        # invalid: port not a number, secret missing
        r = await c.post("/plugins/mail/config", data={"csrf": csrf, "f_host": "imap.example.com", "f_port": "abc", "f_folders": "INBOX"})
        assert r.status_code == 400 and "port" in r.text
        assert not running.settings.config_dir.joinpath("plugins.json").exists() or "imap.example.com" not in running.settings.config_dir.joinpath("plugins.json").read_text()
        # valid
        secret = "Sup3r-S3cret-Passw0rd"
        r = await c.post("/plugins/mail/config", data={"csrf": csrf, "f_host": "imap.example.com", "f_port": "143", "f_use_tls": "1", "f_folders": "INBOX\nArchive", "f_password": secret})
        assert r.status_code == 303 and running.host.manager.is_loaded("mail")
        assert secret not in r.text and secret not in running.settings.config_dir.joinpath("plugins.json").read_text()
        page = await c.get("/plugins/mail")
        assert secret not in page.text and "set; leave blank to keep" in page.text
        assert 'value="imap.example.com"' in page.text
        out = await say(running, "mail", "info")
        assert out == "imap.example.com:143 tls=True folders=INBOX,Archive pw_len=21"
        # blank secret keeps the stored one; reload happened
        await c.post("/plugins/mail/config", data={"csrf": csrf, "f_host": "other.example.com", "f_port": "993", "f_use_tls": "1", "f_folders": "INBOX", "f_password": ""})
        assert (await say(running, "mail", "info")).startswith("other.example.com:993") and (await say(running, "mail", "info")).endswith("pw_len=21")
        # clearing the secret makes the config invalid, so nothing is saved and the plugin keeps running
        r = await c.post("/plugins/mail/config", data={"csrf": csrf, "f_host": "x", "f_port": "1", "clear_password": "1"})
        assert r.status_code == 400 and running.host.manager.is_loaded("mail")
    # no response ever carried the secret, and the audit log has none either
    assert secret not in running.settings.audit_path.read_text()


async def test_policy_form_is_one_tick_box_per_tool(running):
    make_plugin(running.plugins_dir, "mail", IMAPISH)
    running.host.configs.save("mail", values={"host": "h"}, new_secrets={"password": "pw-pw-pw"})
    await running.host.manager.load("mail")
    async with running.admin() as (c, csrf):
        async def tools():
            async with mcp(running, "mail") as m:
                return sorted(t.name for t in (await m.list_tools()).tools)

        assert await tools() == ["info"]
        page = (await c.get("/plugins/mail")).text
        assert 'type="checkbox" id="tool_info"' in page and 'name="tool_mutate"' in page and "textarea id=\"enable_tools\"" not in page
        assert re.search(r'name="tool_info" value="1" checked', page) and not re.search(r'name="tool_mutate" value="1" checked', page)
        base = {"csrf": csrf, "rate_limit_per_minute": "60", "max_output_bytes": "65536"}
        await c.post("/plugins/mail/policy", data={**base, "tool_info": "1"})
        assert await tools() == ["info"]  # the write tool is still off
        await c.post("/plugins/mail/policy", data={**base, "tool_info": "1", "tool_mutate": "1"})
        assert await tools() == ["info", "mutate"]
        assert re.search(r'name="tool_mutate" value="1" checked', (await c.get("/plugins/mail")).text)
        pol = running.host.configs.get("mail").policy
        assert pol.read_only is False and pol.enable_tools == ["mutate"] and pol.deny_tools == []
        await c.post("/plugins/mail/policy", data={**base, "tool_mutate": "1"})  # untick the read tool
        assert await tools() == ["mutate"]
        await c.post("/plugins/mail/policy", data={**base, "tool_info": "1"})  # untick the write tool: back to read-only
        assert await tools() == ["info"] and running.host.configs.get("mail").policy.read_only is True
        r = await c.post("/plugins/mail/policy", data={**base, "max_output_bytes": "5", "tool_info": "1"})
        assert r.status_code == 400
        await c.post("/plugins/mail/action", data={"csrf": csrf, "action": "unload"})  # not loaded: tool choices are kept, numbers update
        await c.post("/plugins/mail/policy", data={**base, "rate_limit_per_minute": "7"})
        pol = running.host.configs.get("mail").policy
        assert pol.rate_limit_per_minute == 7 and pol.read_only is True


async def test_access_page_revokes_grants_and_clients(running):
    reg, tok = await get_tokens(running, "hello")
    async with running.admin() as (c, csrf):
        page = await c.get("/access")
        assert "Test client" in page.text and "hello" in page.text
        grant = running.host.store.list_grants()[0]["id"]
        r = await c.post("/access/revoke", data={"csrf": csrf, "grant": grant})
        assert r.status_code == 303
        async with running.client() as pub:
            r = await pub.post("/hello", headers={"Authorization": f"Bearer {tok['access_token']}"}, json={})
            assert r.status_code == 401
            ref = await pub.post("/oauth/token", data={"grant_type": "refresh_token", "refresh_token": tok["refresh_token"], "client_id": reg["client_id"]})
            assert ref.json()["error"] == "invalid_grant"
        await c.post("/access/revoke", data={"csrf": csrf, "client": reg["client_id"]})
        assert running.host.store.get_client(reg["client_id"]).revoked


async def test_add_preregistered_client_shows_secret_once_and_stores_hash(running):
    async with running.admin() as (c, csrf):
        r = await c.post("/access/client", data={"csrf": csrf, "name": "Claude", "redirect_uris": "https://claude.ai/api/mcp/auth_callback", "plugin": "hello"})
        assert r.status_code == 200
        secret = re.search(r"<code>(cs_[^<]+)</code>", r.text).group(1)
        cid = re.search(r"<code>(c_[^<]+)</code>", r.text).group(1)
        stored = running.host.store.get_client(cid)
        assert stored.secret_hash and secret not in stored.secret_hash and stored.resource == f"{running.base}/hello"
        assert secret not in (await c.get("/access")).text
        r = await c.post("/access/client", data={"csrf": csrf, "name": "x", "redirect_uris": "javascript:alert(1)"})
        assert r.status_code == 400


async def test_pinned_client_cannot_get_a_token_for_another_plugin(running):
    from .oauth_helpers import authorize, pkce
    from urllib.parse import parse_qs, urlsplit

    make_plugin(running.plugins_dir, "mail", IMAPISH)
    running.host.configs.save("mail", values={"host": "h"}, new_secrets={"password": "pw-pw-pw"})
    await running.host.manager.load("mail")
    async with running.admin() as (c, csrf):
        r = await c.post("/access/client", data={"csrf": csrf, "name": "Pinned", "redirect_uris": "https://claude.ai/api/mcp/auth_callback", "plugin": "hello", "public": "1"})
        cid = re.search(r"<code>(c_[^<]+)</code>", r.text).group(1)
    _, ch = pkce()
    async with running.client() as pub:
        for resource in (f"{running.base}/mail",):
            resp = await authorize(running, pub, cid, ch, resource)
            assert parse_qs(urlsplit(resp.headers["location"]).query)["error"] == ["invalid_target"]
        resp = await authorize(running, pub, cid, ch, None)  # no resource: falls back to the pinned plugin
        assert "code" in parse_qs(urlsplit(resp.headers["location"]).query)


async def test_audit_view_has_names_only(running):
    await say(running, "hello", "say_hello", {"name": "SECRET-ARG-VALUE"})
    async with running.admin() as (c, csrf):
        page = await c.get("/audit")
        assert "say_hello" in page.text and "name" in page.text and "SECRET-ARG-VALUE" not in page.text and "Hello, SECRET" not in page.text
        assert "say_hello" in (await c.get("/audit?plugin=hello")).text
        assert "say_hello" not in (await c.get("/audit?plugin=other")).text


async def test_markup_in_plugin_text_is_escaped(running):
    make_plugin(running.plugins_dir, "xss", 'from mcpopus.plugin import Plugin\nclass P(Plugin): pass\nasync def setup(host): await host.add_plugin(P(host.context))\n',
                extra_toml="")
    (running.plugins_dir / "xss" / "plugin.toml").write_text('name = "xss"\nversion = "1.0.0"\ndescription = "<script>alert(1)</script>"\n')
    await running.host.manager.load("xss")
    async with running.admin() as (c, _):
        page = await c.get("/")
        assert "<script>alert(1)</script>" not in page.text and "&lt;script&gt;" in page.text


async def test_first_admin_sign_in_forces_authenticator_setup(running):
    from mcpopus import credentials

    box = running.settings.secret_box
    running.host.store.set_credential("admin", credentials.hash_password(ADMIN_PASSWORD), "")  # password set, no authenticator
    async with httpx2.AsyncClient(base_url=running.admin_base, follow_redirects=False) as c:
        r = await c.post("/login", data={"password": "wrong password here!", "totp": ""})
        assert r.status_code == 401
        r = await c.post("/login", data={"password": ADMIN_PASSWORD})
        assert r.status_code == 303 and r.headers["location"] == "/enrol"
        for path in ("/", "/access", "/audit", "/plugins/hello", "/security"):
            assert (await c.get(path)).headers["location"] == "/enrol"  # nothing else until set up
        page = await c.get("/enrol")
        secret = re.search(r"<dt>Key</dt><dd><code>([A-Z2-7]+)</code>", page.text).group(1)
        csrf = re.search(r'name="csrf" value="([^"]+)"', page.text).group(1)
        assert (await c.get("/enrol")).text.count(secret) >= 1  # reload keeps the same key
        bad = await c.post("/enrol", data={"csrf": csrf, "totp": "000000"})
        assert bad.status_code == 400 and running.host.store.get_credential("admin")["totp_secret_enc"] == ""
        assert (await c.post("/enrol", data={"totp": credentials.totp_at(secret, __import__("time").time() + running.clock.offset)})).status_code == 403  # csrf
        code = credentials.totp_at(secret, __import__("time").time() + running.clock.offset)
        ok = await c.post("/enrol", data={"csrf": csrf, "totp": code})
        assert ok.status_code == 303 and (await c.get("/")).status_code == 200
        assert box.decrypt(running.host.store.get_credential("admin")["totp_secret_enc"], "credential:admin:totp") == secret
    # from now on the code is required, and the setup code cannot be replayed
    async with httpx2.AsyncClient(base_url=running.admin_base, follow_redirects=False) as c:
        assert (await c.post("/login", data={"password": ADMIN_PASSWORD})).status_code == 401
        assert (await c.post("/login", data={"password": ADMIN_PASSWORD, "totp": code})).status_code == 401


async def test_oauth_authenticator_is_set_up_from_the_security_page(running):
    from mcpopus import credentials

    from .oauth_helpers import authorize, pkce, register

    running.host.store.set_credential("oauth", credentials.hash_password("oauth password for tests"), "")
    async with running.client() as pub:  # not enrolled: sign-in is refused, whatever code is given
        reg = await register(pub)
        _, ch = pkce()
        r = await authorize(running, pub, reg["client_id"], ch, f"{running.base}/hello", password="oauth password for tests", totp="123456")
        assert r.status_code == 401
    async with running.admin() as (c, csrf):
        page = await c.get("/security")
        assert "authenticator not set up" in page.text
        r = await c.post("/security/start", data={"csrf": csrf, "realm": "oauth"})
        assert r.headers["location"] == "/enrol"
        page = await c.get("/enrol")
        secret = re.search(r"<dt>Key</dt><dd><code>([A-Z2-7]+)</code>", page.text).group(1)
        assert "connector sign-in" in page.text
        code = credentials.totp_at(secret, __import__("time").time() + running.clock.offset)
        assert (await c.post("/enrol", data={"csrf": csrf, "totp": code})).status_code == 303
        assert "authenticator set up" in (await c.get("/security")).text
        r = await c.post("/security/start", data={"csrf": csrf, "realm": "nonsense"})
        assert r.status_code == 400
    running.totp_secret = secret
    async with running.client() as pub:
        _, ch = pkce()
        reg = await register(pub)
        r = await authorize(running, pub, reg["client_id"], ch, f"{running.base}/hello", password="oauth password for tests")
        assert r.status_code == 303 and "code=" in r.headers["location"]


async def test_enrolment_page_shows_a_qr_code_for_the_otpauth_uri(running):
    import html

    from mcpopus import credentials
    from mcpopus.admin import qr_svg

    running.host.store.set_credential("admin", credentials.hash_password(ADMIN_PASSWORD), "")
    async with httpx2.AsyncClient(base_url=running.admin_base, follow_redirects=False) as c:
        await c.post("/login", data={"password": ADMIN_PASSWORD})
        page = (await c.get("/enrol")).text
        secret = re.search(r"<dt>Key</dt><dd><code>([A-Z2-7]+)</code>", page).group(1)
        uri = credentials.provisioning_uri(secret, "mcpopus admin")
        assert "<svg" in page and qr_svg(uri) in page  # the code encodes exactly the shown uri
        assert html.escape(uri) in page or uri in page
        assert "<script" not in page.lower()


async def test_refused_host_is_logged_with_the_value(running, caplog):
    import logging

    caplog.set_level(logging.WARNING, logger="mcpopus.admin")
    async with httpx2.AsyncClient(base_url=running.admin_base) as c:
        assert (await c.get("/", headers={"Host": "pi4.example.ts.net:8081"})).status_code == 421
    assert "pi4.example.ts.net:8081" in caplog.text and "MCPOPUS_ADMIN_ALLOWED_HOSTS" in caplog.text


def test_form_text_values_are_trimmed_but_secrets_are_not():
    from mcpopus.forms import parse
    from mcpopus.plugin import BaseModel, SecretStr

    class C(BaseModel):
        url: str
        port: int = 1
        pw: SecretStr | None = None

    values, secrets, _ = parse(C, {"f_url": "  http://x:5984 \n", "f_port": " 5984 ", "f_pw": " keep spaces "})
    assert values == {"url": "http://x:5984", "port": "5984"} and secrets == {"pw": " keep spaces "}


async def test_home_cards_and_page_titles(running):
    async with running.admin() as (c, _):
        home = await c.get("/")
        assert "<title>MCP Octopus - Home</title>" in home.text and "pcard" in home.text and "hello" in home.text
        plugins = await c.get("/plugins")
        assert "<title>MCP Octopus - Plugins</title>" in plugins.text
        assert "<title>MCP Octopus - Access</title>" in (await c.get("/access")).text
    async with running.admin() as (c, _):
        pass


async def test_admin_session_slides_but_has_an_absolute_limit(running):
    import time

    store = running.host.store
    idle, longest = 168 * 3600, 30 * 86400
    async with running.admin() as (c, _):
        sid = c.cookies.get("mcpopus_admin")
        from mcpopus.crypto import hash_token

        h = hash_token(sid)
        row = store.get_admin_session(h)
        assert abs(row["expires_at"] - row["created_at"] - idle) < 5  # a week, not eight hours
        store._run("UPDATE admin_sessions SET expires_at=? WHERE id_hash=?", (time.time() + 600, h))  # nearly expired
        resp = await c.get("/")
        assert resp.status_code == 200 and "mcpopus_admin" in resp.headers.get("set-cookie", "")
        assert store.get_admin_session(h)["expires_at"] > time.time() + idle - 60  # use renewed it
        store._run("UPDATE admin_sessions SET created_at=?, expires_at=? WHERE id_hash=?", (time.time() - longest + 7200, time.time() + 600, h))
        await c.get("/")
        assert store.get_admin_session(h)["expires_at"] <= time.time() + 7200 + 5  # never past created_at + 30 days
        store._run("UPDATE admin_sessions SET expires_at=? WHERE id_hash=?", (time.time() - 1, h))
        assert (await c.get("/")).status_code == 303  # expired sessions are refused


def test_session_settings_are_validated(monkeypatch, tmp_path):
    import pytest

    from mcpopus.settings import Settings, SettingsError

    from mcpopus.crypto import generate_key

    base = {"MCPOPUS_PUBLIC_URL": "https://mcp.example.com", "MCPOPUS_SECRET_KEY": generate_key()}
    for bad in ("0", "abc", "100000"):
        with pytest.raises(SettingsError, match="IDLE_HOURS"):
            Settings.from_env({**base, "MCPOPUS_ADMIN_SESSION_IDLE_HOURS": bad})
    assert Settings.from_env(base).admin_session_idle_hours == 168.0


async def test_rejected_settings_and_failed_reloads_are_visible(running):
    make_plugin(running.plugins_dir, "alpha", IMAPISH.replace("password: SecretStr", "password: SecretStr = SecretStr('pw-default')").replace("host: str = Field(description=\"Server name\")", "host: str = 'h'"))
    await running.host.manager.load("alpha")
    async with running.admin() as (c, csrf):
        page = (await c.get("/plugins/alpha")).text
        assert "Running version" in page and "applied" in page and "UTC" in page
        bad = await c.post("/plugins/alpha/config", data={"csrf": csrf, "f_port": "not-a-number", "f_host": "h"})
        assert bad.status_code == 400 and "Not saved" in bad.text and "previous settings" in bad.text and "not-a-number" not in bad.text.split("Not saved")[1].split("</p>")[0]
        assert running.host.manager.is_loaded("alpha")  # the old version keeps running
        # a failed reload leaves the old version serving and says so, with a time
        (running.plugins_dir / "alpha" / "__init__.py").write_text("raise RuntimeError('boom')\n")
        try:
            await running.host.manager.reload("alpha")
        except Exception:  # noqa: BLE001
            pass
        page = (await c.get("/plugins/alpha")).text
        assert "previous version still running" in page and "Running version" in page
        assert running.host.manager.states["alpha"].error_at is not None
