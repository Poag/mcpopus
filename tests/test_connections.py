"""Why a client has to sign in again is in the log; stale connections are cleaned up and shown honestly."""

import logging
import time

import httpx2

from mcpopus.store import Client

from .oauth_helpers import get_tokens


def add_dcr(store, cid, age_days):
    store.add_client(Client(cid, None, "Claude", ("https://claude.ai/api/mcp/auth_callback",), "dcr", None, time.time() - age_days * 86400, False))


def test_stale_grants_and_abandoned_clients_are_purged(running):
    st, now = running.host.store, time.time()
    add_dcr(st, "c_old", 3)
    add_dcr(st, "c_never", 3)  # registered, never authorised
    add_dcr(st, "c_new", 0)  # registered a moment ago: kept
    st.add_grant("g_dead", "c_old", "http://x/obsidian", "mcp")
    st._run("UPDATE grants SET created_at=? WHERE id='g_dead'", (now - 10 * 86400,))  # nothing can refresh it, over a week old
    st.add_grant("g_live", "c_old", "http://x/obsidian", "mcp")
    st.add_token("h_ref", "refresh", "g_live", now + 1000)
    act = st.grant_activity()
    assert act["g_dead"]["refresh_until"] is None and act["g_live"]["refresh_until"] is not None
    grants, clients = st.purge_stale()
    assert grants >= 1 and clients >= 1
    assert st.get_grant("g_dead") is None and st.get_grant("g_live") is not None
    assert st.get_client("c_never") is None and st.get_client("c_new") is not None and st.get_client("c_old") is not None


async def test_refresh_refusals_and_token_refusals_say_why(running, caplog):
    caplog.set_level(logging.DEBUG, logger="mcpopus.oauth")
    caplog.set_level(logging.INFO, logger="mcpopus.gateway")
    reg, tok = await get_tokens(running, "hello")
    async with httpx2.AsyncClient(base_url=running.base) as c:
        r = await c.post("/oauth/token", data={"grant_type": "refresh_token", "refresh_token": "rt_garbage", "client_id": reg["client_id"]})
        assert r.status_code == 400 and r.json()["error"] == "invalid_grant"
        assert "refresh refused" in caplog.text and "token not found" in caplog.text and "rt_garbage" not in caplog.text
        # an access token the host does not know: the caller gets the one identical 401, the log says why
        r = await c.post("/hello/", headers={"Authorization": "Bearer at_garbage"}, json={})
        assert r.status_code == 401 and r.text == (await c.post("/hello/", json={})).text
        assert "access token refused" in caplog.text and "unknown" in caplog.text and "at_garbage" not in caplog.text
        # the real token, once its grant is revoked, is refused with that reason
        for g in running.host.store.list_grants():
            running.host.store.revoke_grant(g["id"])
        r = await c.post("/hello/", headers={"Authorization": f"Bearer {tok['access_token']}"}, json={})
        assert r.status_code == 401


async def test_access_page_shows_expired_and_last_refreshed(running):
    await get_tokens(running, "hello")
    st = running.host.store
    gid = st.list_grants()[0]["id"]
    async with running.admin() as (a, _):
        page = (await a.get("/access")).text
        assert "Last refreshed" in page and ">active<" in page
        st._run("DELETE FROM tokens WHERE grant_id=?", (gid,))
        assert ">expired<" in (await a.get("/access")).text


async def test_access_page_ties_grants_to_clients_and_revoked_grants_can_be_removed(running):
    reg, _ = await get_tokens(running, "hello")
    st = running.host.store
    gid = st.list_grants()[0]["id"]
    async with running.admin() as (a, csrf):
        page = (await a.get("/access")).text
        assert page.count(reg["client_id"]) >= 2  # shown against the grant and against the client
        assert "Connected to" in page and ">hello<" in page.replace(" ", "")
        assert "delete_grant" not in page  # an active grant can only be revoked, not removed
        await a.post("/access/revoke", data={"csrf": csrf, "grant": gid})
        page = (await a.get("/access")).text
        assert ">revoked<" in page and 'name="delete_grant"' in page and "hello (revoked)" in page
        r = await a.post("/access/revoke", data={"csrf": csrf, "delete_grant": gid})
        assert "Removed the grant and its now-unused client" in (await a.get(r.headers["location"])).text
        assert st.get_grant(gid) is None and st.get_client(reg["client_id"]) is None
        assert "No such grant" in (await a.get((await a.post("/access/revoke", data={"csrf": csrf, "delete_grant": gid})).headers["location"])).text


async def test_deleting_a_client_leaves_no_grant_or_token_behind(running):
    reg, tok = await get_tokens(running, "hello")
    st = running.host.store
    gid = st.list_grants()[0]["id"]
    st.delete_client(reg["client_id"])
    assert st.get_grant(gid) is None and st._one("SELECT 1 FROM tokens WHERE grant_id=?", (gid,)) is None


async def test_an_expired_token_is_told_to_refresh_but_other_failures_stay_identical(running, caplog):
    caplog.set_level(logging.INFO)
    reg, tok = await get_tokens(running, "hello")
    st = running.host.store
    async with httpx2.AsyncClient(base_url=running.base) as c:
        none = await c.post("/hello/", json={})
        junk = await c.post("/hello/", headers={"Authorization": "Bearer at_unknown_token"}, json={})
        assert none.status_code == junk.status_code == 401 and none.text == junk.text
        assert none.headers["www-authenticate"] == junk.headers["www-authenticate"] and "invalid_token" not in none.headers["www-authenticate"]
        # expire the real token, and run the housekeeping: it is kept for a day, so it is recognised as expired, not unknown
        from mcpopus.crypto import hash_token

        st._run("UPDATE tokens SET expires_at=? WHERE token_hash=?", (time.time() - 60, hash_token(tok["access_token"])))
        st.purge_expired()
        r = await c.post("/hello/", headers={"Authorization": f"Bearer {tok['access_token']}"}, json={})
        assert r.status_code == 401 and r.text == none.text
        assert 'error="invalid_token"' in r.headers["www-authenticate"] and "resource_metadata=" in r.headers["www-authenticate"]
        # a day later it is purged for good
        st._run("UPDATE tokens SET expires_at=? WHERE token_hash=?", (time.time() - 2 * 86400, hash_token(tok["access_token"])))
        st.purge_expired()
        assert st.get_token(hash_token(tok["access_token"])) is None
        # the first refresh of a client since start-up is logged once
        for _ in range(2):
            t = await c.post("/oauth/token", data={"grant_type": "refresh_token", "refresh_token": tok["refresh_token"], "client_id": reg["client_id"]})
            tok = t.json() if t.status_code == 200 else tok
        assert caplog.text.count("refreshed its tokens (first time since start-up)") == 1
