"""Admin UI: a separate Starlette app on an internal-only listener, with its own login."""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
import time
from urllib.parse import urlsplit

import segno
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import RedirectResponse, Response
from starlette.routing import Route

from . import __version__, credentials
from .app import Host
from .crypto import SecretError, ct_equal, hash_token, new_token
from .forms import describe, parse
from .manager import PluginLoadError, PluginState
from .pluginconfig import ConfigError, Policy, secret_fields, validate_config
from .ratelimit import RateLimiter
from .routing import valid_plugin_name
from .sources import SourceError
from .store import Client
from .web import BodyTooLarge, client_ip, html_page, read_form_multi

log = logging.getLogger("mcpopus.admin")
REALM = "admin"
COOKIE = "mcpopus_admin"
ENROL_SECONDS = 3600  # the set-up-only session after a first, password-only sign-in


def host_ok(host_header: str, extra: tuple[str, ...]) -> bool:
    """Admin Host allow-list: IP literals, localhost, and names listed in MCPOPUS_ADMIN_ALLOWED_HOSTS.
    Refusing arbitrary hostnames defeats DNS rebinding against the internal listener."""
    h = host_header.lower().strip()
    if h.startswith("["):  # [v6]:port
        name = h[1 : h.index("]")] if "]" in h else h
    elif h.count(":") == 1:  # name:port or v4:port
        name = h.split(":")[0]
    else:
        name = h
    if name == "localhost" or name in extra:
        return True
    try:
        ipaddress.ip_address(name)
        return True
    except ValueError:
        return False


class Admin:
    def __init__(self, host: Host, extra_hosts: tuple[str, ...] = (), secure_cookie: bool = False) -> None:
        self.h, self.extra_hosts, self.secure_cookie = host, extra_hosts, secure_cookie
        self.login_ip = RateLimiter(5, 900)
        self.login_global = RateLimiter(20, 900)
        self.started = time.time()

    # --------------------------------------------------------------- plumbing
    def app(self) -> Starlette:
        r = [
            Route("/login", self.login, methods=["GET", "POST"]),
            Route("/logout", self.guard(self.logout, allow_enrol=True), methods=["POST"]),
            Route("/enrol", self.guard(self.enrol_page, allow_enrol=True), methods=["GET"]),
            Route("/enrol", self.guard(self.enrol_confirm, allow_enrol=True), methods=["POST"]),
            Route("/security", self.guard(self.security), methods=["GET"]),
            Route("/security/start", self.guard(self.security_start), methods=["POST"]),
            Route("/", self.guard(self.home), methods=["GET"]),
            Route("/plugins", self.guard(self.dashboard), methods=["GET"]),
            Route("/plugins/{name}", self.guard(self.plugin_page), methods=["GET"]),
            Route("/plugins/{name}/action", self.guard(self.plugin_action), methods=["POST"]),
            Route("/plugins/{name}/config", self.guard(self.save_config), methods=["POST"]),
            Route("/plugins/{name}/policy", self.guard(self.save_policy), methods=["POST"]),
            Route("/sources/add", self.guard(self.source_add), methods=["POST"]),
            Route("/sources/{sid}/{action}", self.guard(self.source_action), methods=["POST"]),
            Route("/plugins/{name}/install", self.guard(self.plugin_install), methods=["POST"]),
            Route("/plugins/{name}/uninstall", self.guard(self.plugin_uninstall), methods=["POST"]),
            Route("/access", self.guard(self.access), methods=["GET"]),
            Route("/access/revoke", self.guard(self.revoke), methods=["POST"]),
            Route("/access/client", self.guard(self.add_client), methods=["POST"]),
            Route("/audit", self.guard(self.audit), methods=["GET"]),
        ]
        return Starlette(routes=r, middleware=[])

    def guard(self, fn, allow_enrol: bool = False):
        async def handler(request: Request) -> Response:
            bad = self._host_check(request)
            if bad:
                return bad
            session = self._session(request)
            if session is None:
                return RedirectResponse("/login", status_code=303)
            request.state.session = session
            if session["enrol_only"] and not allow_enrol:
                return RedirectResponse("/enrol", status_code=303)
            renewed = self._renew(session)
            if request.method == "POST":
                try:
                    form = dict(await read_form_multi(request))
                except BodyTooLarge:
                    return html_page("error.html", 413, title="Request too large", message="")
                request.state.form = form
                if not ct_equal(session["csrf"], form.get("csrf", "")):
                    return html_page("error.html", 403, title="Request refused", message="Missing or wrong form token. Reload the page and try again.")
            resp = await fn(request)
            if renewed is not None and not session["enrol_only"]:
                self._set_cookie(resp, request.cookies[COOKIE], renewed - time.time())
            return resp

        return handler

    def _lifetimes(self) -> tuple[float, float]:
        s = self.h.settings
        return s.admin_session_idle_hours * 3600, s.admin_session_max_days * 86400

    def _renew(self, session) -> float | None:
        """Sliding expiry: use keeps a session alive, up to the absolute maximum. Written at most about once an hour."""
        if session["enrol_only"]:
            return None
        idle, longest = self._lifetimes()
        now = time.time()
        new = min(now + idle, session["created_at"] + longest)
        if new - session["expires_at"] < 3600:
            return None
        self.h.store.extend_admin_session(session["id_hash"], new)
        return new

    def _set_cookie(self, resp: Response, sid: str, max_age: float) -> None:
        resp.set_cookie(COOKIE, sid, max_age=max(60, int(max_age)), httponly=True, samesite="strict", secure=self.secure_cookie, path="/")

    def _host_check(self, request: Request) -> Response | None:
        if not host_ok(request.headers.get("host", ""), self.extra_hosts):
            log.warning("admin request refused: Host %r is not allowed; set MCPOPUS_ADMIN_ALLOWED_HOSTS to the name you browse by (allowed now: %s)",
                        request.headers.get("host", "")[:100], ", ".join(self.extra_hosts) or "none")
            return html_page("error.html", 421, title="Misdirected request", message="")
        return None

    def _session(self, request: Request):
        raw = request.cookies.get(COOKIE)
        return self.h.store.get_admin_session(hash_token(raw)) if raw else None

    def _shell(self) -> dict:
        """The header strip of every admin page."""
        secs = int(time.time() - self.started)
        up = f"{secs // 86400}d {secs % 86400 // 3600}h" if secs >= 86400 else f"{secs // 3600}h {secs % 3600 // 60}m" if secs >= 3600 else f"{secs // 60}m"
        states = self.h.manager.status()
        return {"host": self.h.settings.public_host, "version": __version__, "uptime": up,
                "loaded": sum(1 for st in states if self.h.manager.is_loaded(st.name)), "total": len(states)}

    def page(self, request: Request, template: str, status: int = 200, **ctx) -> Response:
        path = request.url.path
        active = "home" if path == "/" else "access" if path.startswith("/access") else "audit" if path.startswith("/audit") else "security" if path.startswith(("/security", "/enrol")) else "plugins"
        return html_page(template, status, csrf=request.state.session["csrf"], shell=self._shell(), active=active, **ctx)

    # ------------------------------------------------------------------ login
    async def login(self, request: Request) -> Response:
        bad = self._host_check(request)
        if bad:
            return bad
        if request.method == "GET":
            return html_page("admin_login.html")
        ip = client_ip(request, False)
        try:
            form = dict(await read_form_multi(request))
        except BodyTooLarge:
            return html_page("error.html", 413, title="Request too large", message="")
        if self.login_ip.blocked(ip) or self.login_global.blocked("all"):
            return html_page("error.html", 429, title="Too many attempts", message="Wait a few minutes.")
        cred = self.h.store.get_credential(REALM)
        ok_pw = await asyncio.to_thread(credentials.verify_password, cred["password_hash"] if cred else None, form.get("password", ""))
        step = None
        enrol = bool(cred) and ok_pw and not cred["totp_secret_enc"]  # first sign-in: password only, then set up the authenticator
        if cred and cred["totp_secret_enc"]:
            try:
                secret = self.h.settings.secret_box.decrypt(cred["totp_secret_enc"], f"credential:{REALM}:totp")
                step = credentials.verify_totp(secret, form.get("totp", ""), cred["totp_last_step"])
            except SecretError:
                log.error("cannot decrypt the admin TOTP secret: wrong MCPOPUS_SECRET_KEY?")
        if not (enrol or (ok_pw and step is not None and self.h.store.advance_totp_step(REALM, step))):
            self.login_ip.record(ip)
            self.login_global.record("all")
            reason = "no admin password is set" if cred is None else "password" if not ok_pw else "authenticator code"
            log.warning("failed admin login from %s: %s", ip, reason)
            return html_page("admin_login.html", 401, error="Those details were not accepted.")
        sid, csrf = new_token("as", 32), new_token("cs", 24)
        life = ENROL_SECONDS if enrol else self._lifetimes()[0]
        self.h.store.add_admin_session(hash_token(sid), csrf, time.time() + life, enrol_only=enrol)
        resp = RedirectResponse("/enrol" if enrol else "/", status_code=303)
        self._set_cookie(resp, sid, life)
        log.info("admin login from %s", ip)
        return resp

    # ------------------------------------------------- authenticator set-up
    def _pending(self, request: Request) -> tuple[str, str] | None:
        s = request.state.session
        if not s["pending_realm"] or not s["pending_totp_enc"]:
            return None
        try:
            return s["pending_realm"], self.h.settings.secret_box.decrypt(s["pending_totp_enc"], "pending-totp")
        except SecretError:
            return None

    def _start_pending(self, request: Request, realm: str) -> tuple[str, str]:
        secret = credentials.new_totp_secret()
        sid = hash_token(request.cookies[COOKIE])
        self.h.store.set_session_pending(sid, realm, self.h.settings.secret_box.encrypt(secret, "pending-totp"))
        return realm, secret

    def _enrol_ctx(self, realm: str, secret: str, error: str = "") -> dict:
        return {"realm": realm, "secret": secret, "uri": credentials.provisioning_uri(secret, f"mcpopus {realm}"), "error": error,
                "qr": qr_svg(credentials.provisioning_uri(secret, f"mcpopus {realm}")),
                "label": "connector sign-in" if realm == "oauth" else "admin"}

    async def enrol_page(self, request: Request) -> Response:
        s = request.state.session
        pending = self._pending(request)
        if pending is None:
            if not s["enrol_only"]:
                return RedirectResponse("/security", status_code=303)
            pending = self._start_pending(request, REALM)
        return self.page(request, "admin_enrol.html", enrol_only=bool(s["enrol_only"]), **self._enrol_ctx(*pending))

    async def enrol_confirm(self, request: Request) -> Response:
        s = request.state.session
        pending = self._pending(request)
        if pending is None:
            return RedirectResponse("/enrol" if s["enrol_only"] else "/security", status_code=303)
        realm, secret = pending
        ip = client_ip(request, False)
        if self.login_ip.blocked(ip) or self.login_global.blocked("all"):
            return html_page("error.html", 429, title="Too many attempts", message="Wait a few minutes.")
        step = credentials.verify_totp(secret, request.state.form.get("totp", ""), 0)
        if step is None:
            self.login_ip.record(ip)
            self.login_global.record("all")
            return self.page(request, "admin_enrol.html", 400, enrol_only=bool(s["enrol_only"]), **self._enrol_ctx(realm, secret, "That code did not match. Check the clock on your device and try again."))
        if not self.h.store.set_totp(realm, self.h.settings.secret_box.encrypt(secret, f"credential:{realm}:totp"), step):
            return html_page("error.html", 400, title="No password set", message="Set the password first (MCPOPUS_%s_PASSWORD or mcpopus init)." % realm.upper())
        sid = hash_token(request.cookies[COOKIE])
        self.h.store.end_enrol_only(sid)
        log.info("%s authenticator set up from the admin UI", realm)
        return RedirectResponse("/security?msg=Authenticator+saved.", status_code=303)

    async def security(self, request: Request) -> Response:
        rows = []
        for realm, label in (("admin", "Admin sign-in"), ("oauth", "Connector sign-in (claude.ai)")):
            cred = self.h.store.get_credential(realm)
            rows.append({"realm": realm, "label": label, "state": "no password set" if cred is None else "authenticator set up" if cred["totp_secret_enc"] else "authenticator not set up: sign-in is refused until it is"})
        return self.page(request, "admin_security.html", rows=rows, flash=request.query_params.get("msg", ""))

    async def security_start(self, request: Request) -> Response:
        realm = request.state.form.get("realm", "")
        if realm not in ("admin", "oauth") or self.h.store.get_credential(realm) is None:
            return html_page("error.html", 400, title="Cannot set up", message="Set that realm's password first.")
        self._start_pending(request, realm)
        return RedirectResponse("/enrol", status_code=303)

    async def logout(self, request: Request) -> Response:
        raw = request.cookies.get(COOKIE)
        if raw:
            self.h.store.delete_admin_session(hash_token(raw))
        resp = RedirectResponse("/login", status_code=303)
        resp.delete_cookie(COOKIE, path="/")
        return resp

    # -------------------------------------------------------------- dashboard
    def _plugin_rows(self) -> list[dict]:
        rows = []
        installed = set(self.h.sources.installed_paths())
        for st in self.h.manager.status():
            ok = valid_plugin_name(st.name)
            rows.append({"st": st, "enabled": self.h.configs.get(st.name).enabled if ok else False,
                         "url": self.h.routing.resource_url(st.name) if ok else "", "from_source": st.name in installed})
        return rows

    async def home(self, request: Request) -> Response:
        rows = self._plugin_rows()
        clients = self.h.store.list_clients()
        grants = [g for g in self.h.store.list_grants() if g["revoked_at"] is None]
        stats = {"plugins": len(rows), "loaded": sum(1 for r in rows if r["st"].status == "loaded"),
                 "tools": sum(len(r["st"].tools) for r in rows if r["st"].status == "loaded"),
                 "problems": sum(1 for r in rows if r["st"].status == "error"),
                 "clients": len(clients), "grants": len(grants)}
        per_plugin = self.h.stats.by_plugin(1)
        for r in rows:
            r["usage"] = per_plugin.get(r["st"].name, {})
        today = self.h.stats.totals(1)
        return self.page(request, "admin_home.html", plugins=rows, stats=stats, today=today, week=self.h.stats.per_day(None, 14), flash=request.query_params.get("msg", ""))

    async def dashboard(self, request: Request) -> Response:
        rows = self._plugin_rows()
        sources = self.h.sources.view()
        for src in sources:
            src["pending"] = await self.h.sources.pending(src["id"]) if src["has_update"] else {}
        total = len(rows)
        q = request.query_params.get("q", "")[:60].strip()
        state = request.query_params.get("state", "")
        if state not in ("", "loaded", "unloaded", "disabled", "error"):
            state = ""
        if q:
            rows = [r for r in rows if q.casefold() in r["st"].name.casefold() or q.casefold() in (r["st"].description or "").casefold()]
        if state:
            rows = [r for r in rows if ("disabled" if not r["enabled"] else r["st"].status) == state]
        return self.page(request, "admin_dashboard.html", plugins=rows, total=total, q=q, state=state, sources=sources, flash=request.query_params.get("msg", ""))

    async def plugin_action(self, request: Request) -> Response:
        name = request.path_params["name"]
        action = request.state.form.get("action", "")
        if not valid_plugin_name(name) or action not in ("load", "unload", "reload", "enable", "disable"):
            return html_page("error.html", 404, title="Not found", message="")
        mgr = self.h.manager
        try:
            if action in ("enable", "disable"):
                self.h.configs.save(name, enabled=action == "enable")
                if action == "enable" and not mgr.is_loaded(name):
                    await mgr.load(name)
                elif action == "disable":
                    if mgr.is_loaded(name):
                        await mgr.unload(name)
                    mgr.states.setdefault(name, PluginState(name)).status = "disabled"
            else:
                await getattr(mgr, action)(name)
            msg = f"{name}: {action} done"
        except PluginLoadError as e:
            msg = f"{name}: {action} failed: {e}"
        return RedirectResponse(f"/plugins?msg={_q(msg)}", status_code=303)

    # ------------------------------------------------------------- sources
    @staticmethod
    def _need_trust(form: dict[str, str]) -> None:
        if form.get("trust") != "1":
            raise SourceError("Tick the box to confirm you trust this code: plugins run inside the host and can read its secrets.")

    def _back(self, msg: str) -> Response:
        return RedirectResponse(f"/plugins?msg={_q(msg)}#sources", status_code=303)

    async def source_add(self, request: Request) -> Response:
        f = request.state.form
        try:
            self._need_trust(f)
            sid = self.h.sources.add(f.get("url", ""), f.get("ref", ""))
            await self.h.sources.fetch(sid)
            msg = "Source added and fetched. Choose which plugins to install."
        except SourceError as e:
            msg = f"Could not add the source: {e}"
        return self._back(msg)

    async def source_action(self, request: Request) -> Response:
        sid, action = request.path_params["sid"], request.path_params["action"]
        if not re.fullmatch(r"[0-9a-f]{12}", sid) or action not in ("fetch", "apply", "remove"):
            return html_page("error.html", 404, title="Not found", message="")
        try:
            if action == "fetch":
                pending = await self.h.sources.fetch(sid)
                msg = "Fetched. An update is available: review it below." if pending else "Fetched. Already up to date."
            elif action == "apply":
                self._need_trust(request.state.form)
                names = await self.h.sources.apply(sid)
                results = []
                for n in names:
                    try:
                        await (self.h.manager.reload(n) if self.h.manager.is_loaded(n) else self.h.manager.load(n))
                        results.append(f"{n} reloaded")
                    except PluginLoadError as e:
                        results.append(f"{n} failed ({e})")
                msg = "Update applied. " + ("; ".join(results) if results else "No installed plugins came from this source.")
            else:
                self.h.sources.remove(sid)
                msg = "Source removed."
        except SourceError as e:
            msg = str(e)
        return self._back(msg)

    async def plugin_install(self, request: Request) -> Response:
        name, f = request.path_params["name"], request.state.form
        try:
            self._need_trust(f)
            self.h.sources.install(name, f.get("source", ""), self.h.settings.plugins_dir)
            self.h.manager.discover()
            try:
                await self.h.manager.load(name)
                msg = f"{name} installed and loaded. Its endpoint is {self.h.routing.resource_url(name)}; configure it on its page."
            except PluginLoadError as e:
                msg = f"{name} installed, but it did not load yet: {e}. Open its page to configure it."
        except SourceError as e:
            msg = str(e)
        return self._back(msg)

    async def plugin_uninstall(self, request: Request) -> Response:
        name = request.path_params["name"]
        try:
            if self.h.manager.is_loaded(name):
                await self.h.manager.unload(name)
            self.h.sources.uninstall(name)
            self.h.manager.discover()
            msg = f"{name} uninstalled. Its settings and data are kept."
        except (SourceError, PluginLoadError) as e:
            msg = str(e)
        return self._back(msg)

    # --------------------------------------------------------- plugin config
    def _plugin_ctx(self, name: str, values=None, secrets_set=None, error: str = "", flash: str = "", policy: Policy | None = None) -> dict:
        settings = self.h.configs.get(name)
        model = self.h.manager.config_model(name)
        fields = describe(model, values if values is not None else settings.values, secrets_set if secrets_set is not None else set(settings.secrets)) if model else []
        lp = self.h.manager.get(name)
        pol = policy or settings.policy
        tools = [{"name": m.name, "tier": m.tier, "kind": m.kind, "untrusted": m.untrusted, "served": m.name in lp.tools if m.kind == "tool" else pol.allows(m.name, "read")}
                 for m in (lp.declared if lp else [])]
        return {"name": name, "fields": fields, "policy": pol, "tools": tools, "state": self.h.manager.states.get(name),
                "enabled": settings.enabled, "error": error, "flash": flash, "has_model": model is not None,
                "url": self.h.routing.resource_url(name),
                "usage_day": self.h.stats.totals(1, plugin=name), "usage_week": self.h.stats.totals(7, plugin=name),
                "usage_tools": self.h.stats.by_tool(name, 7), "usage_counters": self.h.stats.counters(name, 30),
                "usage_days": self.h.stats.per_day(name, 14)}

    async def plugin_page(self, request: Request) -> Response:
        name = request.path_params["name"]
        if not valid_plugin_name(name) or name not in self.h.manager.discover():
            return html_page("error.html", 404, title="Not found", message="")
        return self.page(request, "admin_plugin.html", **self._plugin_ctx(name, flash=request.query_params.get("msg", "")))

    async def save_config(self, request: Request) -> Response:
        name = request.path_params["name"]
        if not valid_plugin_name(name) or name not in self.h.manager.discover():
            return html_page("error.html", 404, title="Not found", message="")
        model = self.h.manager.config_model(name)
        if model is None:
            return html_page("error.html", 400, title="No settings", message="This plugin has no configuration.")
        values, new_secrets, clear = parse(model, request.state.form)
        stored = self.h.configs.get(name)
        try:  # validate everything, including the secrets that stay unchanged, before saving anything
            merged = {**self.h.configs.decrypted_secrets(name, stored), **new_secrets}
            for c in clear:
                merged.pop(c, None)
            validate_config(model, values, merged)
        except ConfigError as e:
            return self.page(request, "admin_plugin.html", 400, **self._plugin_ctx(name, values=values, error=str(e)))
        self.h.configs.save(name, values=values, new_secrets=new_secrets, clear_secrets=clear)
        try:
            await (self.h.manager.reload(name) if self.h.manager.is_loaded(name) else self.h.manager.load(name))
            msg = "Saved and reloaded."
        except PluginLoadError as e:
            msg = f"Saved, but the plugin did not load: {e}"
        return RedirectResponse(f"/plugins/{name}?msg={_q(msg)}", status_code=303)

    async def save_policy(self, request: Request) -> Response:
        name = request.path_params["name"]
        if not valid_plugin_name(name) or name not in self.h.manager.discover():
            return html_page("error.html", 404, title="Not found", message="")
        f = request.state.form
        current = self.h.configs.get(name).policy
        lp = self.h.manager.get(name)
        try:
            if lp is None:  # the plugin is not loaded, so its tools are unknown: leave the tool choices as they are
                keep = dict(read_only=current.read_only, allow_tools=current.allow_tools, deny_tools=current.deny_tools, enable_tools=current.enable_tools)
            else:  # one tick box per tool: ticked is served; read tools are denied when unticked, write and admin tools enabled when ticked
                declared = {m.name: m for m in lp.declared}
                enable = [n for n, m in declared.items() if m.tier != "read" and f.get(f"tool_{n}") == "1"]
                deny = [n for n, m in declared.items() if m.tier == "read" and f.get(f"tool_{n}") != "1"]
                keep = dict(read_only=not enable, allow_tools=[], deny_tools=deny, enable_tools=enable)
            pol = Policy(**keep, rate_limit_per_minute=int(f.get("rate_limit_per_minute", "60")),
                         max_output_bytes=int(f.get("max_output_bytes", "65536")))
            if pol.rate_limit_per_minute < 0 or not 1024 <= pol.max_output_bytes <= 4 * 1024 * 1024:
                raise ValueError
        except ValueError:
            return self.page(request, "admin_plugin.html", 400, **self._plugin_ctx(name, error="Policy values are not valid (output cap 1 KiB to 4 MiB)."))
        self.h.configs.save(name, policy=pol)
        try:
            if self.h.manager.is_loaded(name):
                await self.h.manager.reload(name)
            msg = "Policy saved and applied."
        except PluginLoadError as e:
            msg = f"Policy saved, but reload failed: {e}"
        return RedirectResponse(f"/plugins/{name}?msg={_q(msg)}", status_code=303)

    # ------------------------------------------------------------------ access
    async def access(self, request: Request) -> Response:
        clients = self.h.store.list_clients()
        grants = self.h.store.list_grants()
        shown = []
        for g in grants:
            plugin = self.h.routing.plugin_for_resource(g["resource"]) or g["resource"]
            shown.append({"id": g["id"], "client": g["client_name"], "plugin": plugin, "created": time.strftime("%Y-%m-%d %H:%M", time.gmtime(g["created_at"])), "revoked": g["revoked_at"] is not None})
        return self.page(request, "admin_access.html", usage=self.h.stats.by_client(30), clients=clients, grants=shown, flash=request.query_params.get("msg", ""),
                         plugins=self.h.manager.discover(), default_redirect=self.h.settings.allowed_redirect_uris[0])

    async def revoke(self, request: Request) -> Response:
        f = request.state.form
        if f.get("grant"):
            ok = self.h.store.revoke_grant(f["grant"])
            msg = "Grant revoked." if ok else "No such active grant."
        elif f.get("client"):
            msg = "Client revoked, with every grant it holds." if self.h.store.revoke_client(f["client"]) else "No such client."
        elif f.get("delete_client"):
            self.h.store.revoke_client(f["delete_client"])
            self.h.store.delete_client(f["delete_client"])
            msg = "Client deleted."
        else:
            msg = "Nothing to revoke."
        return RedirectResponse(f"/access?msg={_q(msg)}", status_code=303)

    async def add_client(self, request: Request) -> Response:
        f = request.state.form
        uris = [u.strip() for u in f.get("redirect_uris", "").splitlines() if u.strip()]
        plugin = f.get("plugin", "")
        bad = not uris or len(uris) > 5 or any(urlsplit(u).scheme not in ("https", "http") or not urlsplit(u).netloc for u in uris)
        if bad or (plugin and not valid_plugin_name(plugin)):
            return self.page(request, "error.html", 400, title="Invalid client", message="Give one to five http(s) redirect URIs.")
        public = f.get("public") == "1"
        secret = None if public else new_token("cs")
        client = Client(new_token("c", 16), hash_token(secret) if secret else None, f.get("name", "Client")[:80] or "Client", tuple(uris),
                        "preregistered", self.h.routing.resource_url(plugin) if plugin else None, time.time(), False)
        self.h.store.add_client(client)
        return self.page(request, "admin_secret_once.html", client=client, secret=secret)

    # ------------------------------------------------------------------- audit
    async def audit(self, request: Request) -> Response:
        plugin = request.query_params.get("plugin", "")
        rows = [r for r in self.h.audit.tail(500) if not plugin or r.get("plugin") == plugin][:200]
        return self.page(request, "admin_audit.html", rows=rows, plugin=plugin)


def qr_svg(data: str) -> str:
    """Inline SVG QR code for an otpauth:// URI. Light background and quiet zone, so it scans in dark mode too.
    The input is built from a base32 secret and a fixed label; the SVG is generated by segno, not assembled from input."""
    return segno.make(data, error="m").svg_inline(scale=5, border=4, dark="#000000", light="#ffffff", omitsize=False)


def _q(text: str) -> str:
    from urllib.parse import quote

    return quote(text[:300])


def build_admin_app(host: Host, extra_hosts: tuple[str, ...] = (), secure_cookie: bool = False) -> Starlette:
    return Admin(host, extra_hosts, secure_cookie).app()
