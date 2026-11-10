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
