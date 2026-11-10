"""OAuth 2.1 authorization server for a single owner, with per-plugin resource binding.

Implements: RFC 6749 authorization code grant and refresh, RFC 7636 PKCE (S256 only),
RFC 7591 dynamic client registration, RFC 7009 revocation, RFC 8414 metadata,
RFC 8707 resource indicators, RFC 9207 iss parameter, and RFC 9728 protected resource
metadata (the resource-server side is served here too, see prm()).
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import logging
import re
import time
import uuid
from collections.abc import Callable
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from starlette.requests import Request
from starlette.responses import RedirectResponse, Response
from starlette.routing import Route

from . import credentials
from .crypto import SecretError, ct_equal, hash_token, new_token
from .ratelimit import RateLimiter
from .routing import Routing
from .settings import LOOPBACK_HOSTS, Settings
from .store import Client, Principal, Store
from .web import BodyTooLarge, client_ip, html_page, json_response, read_body, read_form_multi

log = logging.getLogger("mcpopus.oauth")
diag = logging.getLogger("mcpopus.oauth.diag")  # what clients actually send; no secrets

SCOPE = "mcp"
PKCE_RE = re.compile(r"^[A-Za-z0-9\-._~]{43,128}$")
CHALLENGE_RE = re.compile(r"^[A-Za-z0-9\-_]{43}$")
REALM = "oauth"
MAX_FAILURES_PER_REQUEST = 5


class OAuthError(Exception):
    def __init__(self, error: str, description: str = "", status: int = 400) -> None:
        self.error, self.description, self.status = error, description, status


def _s256(verifier: str) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")


def _is_loopback(uri: str) -> bool:
    p = urlsplit(uri)
    return p.scheme == "http" and (p.hostname or "") in LOOPBACK_HOSTS


def _same_uri(registered: str, presented: str) -> bool:
    """Exact match, except that loopback redirect URIs match with the port ignored
    (RFC 8252 section 7.3; Claude Code uses an ephemeral loopback port)."""
    if registered == presented:
        return True
    if _is_loopback(registered) and _is_loopback(presented):
        a, b = urlsplit(registered), urlsplit(presented)
        return (a.hostname, a.path, a.query) == (b.hostname, b.path, b.query)
    return False


def _add_params(uri: str, params: dict[str, str]) -> str:
    p = urlsplit(uri)
    q = parse_qsl(p.query, keep_blank_values=True) + [(k, v) for k, v in params.items() if v is not None]
    return urlunsplit((p.scheme, p.netloc, p.path, urlencode(q), ""))


class OAuthServer:
    def __init__(
        self,
        settings: Settings,
        store: Store,
        routing: Routing,
        plugin_loaded: Callable[[str], bool],
    ) -> None:
        self.s, self.store, self.routing, self.plugin_loaded = settings, store, routing, plugin_loaded
        # Login failures: per client address and across everyone, so that a
        # distributed guesser is also slowed. The global limit can lock the owner
        # out for the window; that is the accepted cost (see SECURITY.md).
        self.login_ip = RateLimiter(5, 900)
        self.login_global = RateLimiter(20, 900)
        self.register_ip = RateLimiter(10, 3600)
        self.token_ip = RateLimiter(60, 60)
        self.token_client_failures = RateLimiter(10, 300)

    # ------------------------------------------------------------------ routes
    def routes(self) -> list[Route]:
        return [
            Route("/.well-known/oauth-authorization-server", self.as_metadata, methods=["GET"]),
            Route("/oauth/register", self.register, methods=["POST"]),
            Route("/oauth/authorize", self.authorize_get, methods=["GET"]),
            Route("/oauth/authorize", self.authorize_post, methods=["POST"]),
            Route("/oauth/token", self.token, methods=["POST"]),
            Route("/oauth/revoke", self.revoke, methods=["POST"]),
        ]

    # --------------------------------------------------------------- discovery
    async def as_metadata(self, request: Request) -> Response:
        base = self.s.issuer
        return json_response(
            {
                "issuer": base,
                "authorization_endpoint": f"{base}/oauth/authorize",
                "token_endpoint": f"{base}/oauth/token",
                "registration_endpoint": f"{base}/oauth/register",
                "revocation_endpoint": f"{base}/oauth/revoke",
                "response_types_supported": ["code"],
                "grant_types_supported": ["authorization_code", "refresh_token"],
                "code_challenge_methods_supported": ["S256"],
                "token_endpoint_auth_methods_supported": ["none", "client_secret_post", "client_secret_basic"],
                "scopes_supported": [SCOPE],
                "authorization_response_iss_parameter_supported": True,
            },
            headers={"Cache-Control": "public, max-age=300"},
        )

    def prm(self, plugin: str) -> dict:
        """RFC 9728 protected resource metadata. Served for any syntactically valid
        plugin name, so that its existence cannot be probed."""
        return {
            "resource": self.routing.resource_url(plugin),
            "authorization_servers": [self.s.issuer],
            "bearer_methods_supported": ["header"],
            "scopes_supported": [SCOPE],
        }

    # ------------------------------------------------------------ registration
    def _redirect_allowed(self, uri: str) -> bool:
        p = urlsplit(uri)
        if p.fragment or not p.scheme or not p.netloc or "@" in p.netloc:
            return False
        for allowed in self.s.allowed_redirect_uris:
            if allowed == "loopback":
                if _is_loopback(uri):
                    return True
            elif allowed == uri:
                return True
        return False

    async def register(self, request: Request) -> Response:
        ip = client_ip(request, self.s.trust_proxy_headers)
        if not self.register_ip.hit(ip):
            return json_response({"error": "temporarily_unavailable"}, 429)
        try:
            body = await read_body(request, 8192)
            import json

            data = json.loads(body or b"{}")
            if not isinstance(data, dict):
                raise ValueError
        except (BodyTooLarge, ValueError):
            return json_response({"error": "invalid_client_metadata", "error_description": "invalid JSON body"}, 400)
        diag.debug("dcr request keys=%s", sorted(data.keys()))
        uris = data.get("redirect_uris")
        if not isinstance(uris, list) or not (1 <= len(uris) <= 5) or not all(isinstance(u, str) and len(u) <= 512 for u in uris):
            return json_response({"error": "invalid_redirect_uri", "error_description": "redirect_uris required"}, 400)
        rejected = [u for u in uris if not self._redirect_allowed(u)]
        if rejected:
            log.warning("dcr rejected redirect_uri(s): %s", rejected)
            return json_response({"error": "invalid_redirect_uri", "error_description": "redirect URI not permitted"}, 400)
        method = data.get("token_endpoint_auth_method", "none")
        if method not in ("none", "client_secret_post", "client_secret_basic"):
            return json_response({"error": "invalid_client_metadata", "error_description": "unsupported auth method"}, 400)
        grants = data.get("grant_types", ["authorization_code"])
        if not isinstance(grants, list) or not set(grants) <= {"authorization_code", "refresh_token"}:
            return json_response({"error": "invalid_client_metadata", "error_description": "unsupported grant type"}, 400)
        name = re.sub(r"[^\w .\-()']", "?", str(data.get("client_name") or "Unnamed application"))[:80]

        self.store.prune_unused_dcr_clients(time.time() - 86400)
        if self.store.count_dcr_clients() >= self.s.max_dcr_clients:
            return json_response({"error": "temporarily_unavailable"}, 503)

        secret = new_token("cs") if method != "none" else None
        client = Client(
            client_id=new_token("c", 16), secret_hash=hash_token(secret) if secret else None, name=name,
            redirect_uris=tuple(uris), kind="dcr", resource=None, created_at=time.time(), revoked=False,
        )
        self.store.add_client(client)
        out = {
            "client_id": client.client_id,
            "client_id_issued_at": int(client.created_at),
            "client_name": name,
            "redirect_uris": list(uris),
            "token_endpoint_auth_method": method,
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "scope": SCOPE,
        }
        if secret:
            out["client_secret"] = secret
            out["client_secret_expires_at"] = 0
        return json_response(out, 201)

    # --------------------------------------------------------------- authorise
    def _error_page(self, title: str, message: str, status: int = 400) -> Response:
        return html_page("error.html", status, title=title, message=message)

    def _resolve_resource(self, client: Client, presented: list[str]) -> str:
        """Decide which plugin resource the grant is bound to.

        1. A `resource` parameter (RFC 8707), which must name a loaded plugin.
        2. Otherwise, the plugin the client is pinned to (pre-registered clients).
        3. Otherwise reject: binding a token to 'whatever the client likes' would
           defeat the isolation requirement. See docs/SPIKE.md for what to report
           if Claude sends no resource parameter.
        """
        if len(presented) > 1:
            raise OAuthError("invalid_target", "exactly one resource is accepted")
        resource = presented[0] if presented else client.resource
        if not resource:
            raise OAuthError("invalid_target", "no resource indicator was supplied")
        plugin = self.routing.plugin_for_resource(resource)
        if plugin is None or not self.plugin_loaded(plugin):
            raise OAuthError("invalid_target", "unknown resource")
        canonical = self.routing.resource_url(plugin)
        if client.resource and self.routing.plugin_for_resource(client.resource) != plugin:
            raise OAuthError("invalid_target", "this client is bound to a different resource")
        return canonical

    async def authorize_get(self, request: Request) -> Response:
        q = request.query_params
        diag.debug(
            "authorize params=%s ua=%r", sorted(q.keys()), request.headers.get("user-agent", "")[:120]
        )
        client = self.store.get_client(q.get("client_id", ""))
        redirect_uri = q.get("redirect_uri", "")
        if client is None or client.revoked:
            return self._error_page("Cannot continue", "Unknown application.")
        registered = [u for u in client.redirect_uris if _same_uri(u, redirect_uri)]
        if not registered:
            return self._error_page("Cannot continue", "The return address does not match this application.")
        state = q.get("state")

        def fail(error: str, desc: str) -> Response:
            return RedirectResponse(
                _add_params(redirect_uri, {"error": error, "error_description": desc, "state": state or "", "iss": self.s.issuer}),
                status_code=303,
            )

        if q.get("response_type") != "code":
            return fail("unsupported_response_type", "only response_type=code is supported")
        challenge = q.get("code_challenge", "")
        if q.get("code_challenge_method") != "S256" or not CHALLENGE_RE.fullmatch(challenge):
            return fail("invalid_request", "PKCE with code_challenge_method=S256 is required")
        try:
            resource = self._resolve_resource(client, q.getlist("resource"))
        except OAuthError as e:
            diag.debug("authorize rejected: %s (resource param present=%s)", e.description, "resource" in q)
            return fail(e.error, e.description)
        scope = SCOPE

        req_id, csrf = new_token("ar", 18), new_token("cs", 18)
        self.store.add_auth_request(
            id=req_id, client_id=client.client_id, redirect_uri=redirect_uri, state=state,
            code_challenge=challenge, resource=resource, scope=scope, csrf=csrf, expires_at=time.time() + 600,
        )
        return self._render_authorize(req_id, csrf, client, redirect_uri, resource)

    def _render_authorize(self, req_id: str, csrf: str, client: Client, redirect_uri: str, resource: str, error: str = "", status: int = 200) -> Response:
        plugin = self.routing.plugin_for_resource(resource) or "unknown"
        return html_page(
            "authorize.html", status, request_id=req_id, csrf=csrf, plugin=plugin, client_name=client.name,
            redirect_uri=redirect_uri, redirect_host=urlsplit(redirect_uri).netloc,
            loopback=_is_loopback(redirect_uri), error=error,
        )

    async def authorize_post(self, request: Request) -> Response:
        ip = client_ip(request, self.s.trust_proxy_headers)
        try:
            form = dict(await read_form_multi(request))
        except BodyTooLarge:
            return self._error_page("Request too large", "", 413)
        row = self.store.get_auth_request(form.get("request_id", ""))
        if row is None or not ct_equal(row["csrf"], form.get("csrf", "")):
            return self._error_page("Request expired", "Start again from the application.")
        client = self.store.get_client(row["client_id"])
        if client is None or client.revoked:
            return self._error_page("Cannot continue", "Unknown application.")
        redirect_uri = row["redirect_uri"]

        def back(params: dict[str, str]) -> Response:
            params = {**params, "state": row["state"] or "", "iss": self.s.issuer}
            return RedirectResponse(_add_params(redirect_uri, params), status_code=303)

        if form.get("decision") == "deny":
            self.store.delete_auth_request(row["id"])
            return back({"error": "access_denied"})
        if form.get("decision") != "approve":
            return self._error_page("Invalid request", "")

        if self.login_ip.blocked(ip) or self.login_global.blocked("all"):
            return html_page("error.html", 429, title="Too many attempts", message="Wait a few minutes, then start again.")

        password, totp = form.get("password", ""), form.get("totp", "")
        cred = self.store.get_credential(REALM)
        ok_pw = await asyncio.to_thread(credentials.verify_password, cred["password_hash"] if cred else None, password)
        step = None
        if cred and cred["totp_secret_enc"]:  # empty means no authenticator enrolled yet: sign-in is refused
            try:
                secret = self.s.secret_box.decrypt(cred["totp_secret_enc"], f"credential:{REALM}:totp")
                step = credentials.verify_totp(secret, totp, cred["totp_last_step"])
            except SecretError:
                log.error("cannot decrypt the %s TOTP secret: wrong MCPOPUS_SECRET_KEY?", REALM)
        if not (ok_pw and step is not None and self.store.advance_totp_step(REALM, step)):
            self.login_ip.record(ip)
            self.login_global.record("all")
            reason = ("no password is set for connector sign-in" if cred is None else "password" if not ok_pw
                      else "the connector authenticator is not set up (admin UI, Sign-in page)" if not cred["totp_secret_enc"] else "authenticator code")
            log.warning("failed owner login from %s: %s", ip, reason)
            if self.store.bump_auth_failure(row["id"]) >= MAX_FAILURES_PER_REQUEST:
                self.store.delete_auth_request(row["id"])
                return self._error_page("Too many attempts", "Start again from the application.", 429)
            return self._render_authorize(row["id"], row["csrf"], client, redirect_uri, row["resource"], "Those details were not accepted.", 401)

        self.store.delete_auth_request(row["id"])
        grant_id = str(uuid.uuid4())
        self.store.add_grant(grant_id, client.client_id, row["resource"], row["scope"])
        code = new_token("ac")
        self.store.add_code(hash_token(code), grant_id, client.client_id, redirect_uri, row["code_challenge"], time.time() + self.s.code_ttl)
        log.info("authorised client %s for %s", client.client_id, row["resource"])
        return back({"code": code})

    # ------------------------------------------------------------------- token
    def _authenticate_client(self, request: Request, form: dict[str, str]) -> Client:
        client_id, secret = form.get("client_id", ""), form.get("client_secret")
        auth = request.headers.get("authorization", "")
        if auth.lower().startswith("basic "):
            try:
                from urllib.parse import unquote

                user, _, pw = base64.b64decode(auth[6:]).decode().partition(":")
                client_id, secret = unquote(user), unquote(pw)
            except (ValueError, UnicodeDecodeError):
                raise OAuthError("invalid_client", "malformed credentials", 401) from None
        client = self.store.get_client(client_id)
        # Same error for unknown client, revoked client and wrong secret.
        bad = OAuthError("invalid_client", "client authentication failed", 401)
        if client is None or client.revoked:
            raise bad
        if client.secret_hash is not None:
            if not secret or not ct_equal(client.secret_hash, hash_token(secret)):
                if self.token_client_failures.hit(client_id):
                    raise bad
                raise OAuthError("invalid_client", "too many failures", 429)
        return client

    def _issue(self, grant_id: str, scope: str) -> dict:
        access, refresh = new_token("at"), new_token("rt")
        now = time.time()
        self.store.add_token(hash_token(access), "access", grant_id, now + self.s.access_token_ttl)
        self.store.add_token(hash_token(refresh), "refresh", grant_id, now + self.s.refresh_token_ttl)
        return {
            "access_token": access, "token_type": "Bearer", "expires_in": self.s.access_token_ttl,
            "refresh_token": refresh, "scope": scope,
        }

    async def token(self, request: Request) -> Response:
        ip = client_ip(request, self.s.trust_proxy_headers)
        if not self.token_ip.hit(ip):
            return json_response({"error": "temporarily_unavailable"}, 429)
        try:
            if "application/x-www-form-urlencoded" not in request.headers.get("content-type", ""):
                raise OAuthError("invalid_request", "content type must be application/x-www-form-urlencoded", 415)
            pairs = await read_form_multi(request)
            form = dict(pairs)
            client = self._authenticate_client(request, form)
            grant_type = form.get("grant_type")
            diag.debug("token grant_type=%s params=%s", grant_type, sorted(form.keys()))
            if grant_type == "authorization_code":
                out = self._code_grant(client, form, [v for k, v in pairs if k == "resource"])
            elif grant_type == "refresh_token":
                out = self._refresh_grant(client, form)
            else:
                raise OAuthError("unsupported_grant_type", "")
            return json_response(out)
        except BodyTooLarge:
            return json_response({"error": "invalid_request"}, 413)
        except OAuthError as e:
            body = {"error": e.error}
            if e.description:
                body["error_description"] = e.description
            headers = {"WWW-Authenticate": 'Basic realm="mcpopus"'} if e.status == 401 else None
            return json_response(body, e.status, headers)

    def _code_grant(self, client: Client, form: dict[str, str], resources: list[str]) -> dict:
        code = form.get("code", "")
        row, first_use = self.store.consume_code(hash_token(code)) if code else (None, False)
        invalid = OAuthError("invalid_grant", "the authorisation code is invalid or has expired")
        if row is None:
            raise invalid
        if not first_use:
            # Replay of a code: treat as theft and revoke everything issued from it.
            self.store.revoke_grant(row["grant_id"])
            log.warning("authorisation code reuse; grant %s revoked", row["grant_id"])
            raise invalid
        if row["expires_at"] < time.time() or row["client_id"] != client.client_id:
            raise invalid
        if form.get("redirect_uri") != row["redirect_uri"]:
            raise invalid
        verifier = form.get("code_verifier", "")
        if not PKCE_RE.fullmatch(verifier) or not ct_equal(_s256(verifier), row["code_challenge"]):
            raise invalid
        grant = self.store.get_grant(row["grant_id"])
        if grant is None or grant["revoked_at"] is not None:
            raise invalid
        if resources and (len(resources) > 1 or self.routing.plugin_for_resource(resources[0]) != self.routing.plugin_for_resource(grant["resource"])):
            raise OAuthError("invalid_target", "resource does not match the authorisation")
        return self._issue(grant["id"], grant["scope"])

    def _refresh_grant(self, client: Client, form: dict[str, str]) -> dict:
        token = form.get("refresh_token", "")
        h = hash_token(token)
        row = self.store.get_token(h) if token else None
        invalid = OAuthError("invalid_grant", "the refresh token is invalid or has expired")

        def refused(reason: str) -> OAuthError:  # the client sees one error; the owner's log says why (this is what forces a re-sign-in)
            log.warning("refresh refused for client %s: %s", client.client_id, reason)
            return invalid

        if row is None or row["kind"] != "refresh":
            raise refused("token not found (never issued here, or purged after it expired)" if row is None else "not a refresh token")
        grant = self.store.get_grant(row["grant_id"])
        if grant is None or grant["revoked_at"] is not None or grant["client_id"] != client.client_id:
            raise refused("grant is gone or revoked" if grant is None or grant["revoked_at"] is not None else "token belongs to another client")
        if row["used_at"] is not None:
            # A rotated refresh token came back: someone holds a stale copy.
            self.store.revoke_grant(grant["id"])
            log.warning("refresh token reuse; grant %s revoked", grant["id"])
            raise invalid
        if row["expires_at"] < time.time():
            raise refused("refresh token expired")
        if not self.store.mark_refresh_used(h):
            raise refused("lost a race: the same refresh token was presented twice at once")
        diag.debug("refresh ok client=%s grant=%s", client.client_id, grant["id"])
        return self._issue(grant["id"], grant["scope"])

    # ------------------------------------------------------------------ revoke
    async def revoke(self, request: Request) -> Response:
        ip = client_ip(request, self.s.trust_proxy_headers)
        if not self.token_ip.hit(ip):
            return json_response({"error": "temporarily_unavailable"}, 429)
        try:
            form = dict(await read_form_multi(request))
            client = self._authenticate_client(request, form)
        except OAuthError as e:
            return json_response({"error": e.error}, e.status)
        except BodyTooLarge:
            return json_response({"error": "invalid_request"}, 413)
        token = form.get("token", "")
        row = self.store.get_token(hash_token(token)) if token else None
        if row:
            grant = self.store.get_grant(row["grant_id"])
            if grant and grant["client_id"] == client.client_id:
                if row["kind"] == "refresh":
                    self.store.revoke_grant(grant["id"])
                else:
                    self.store.delete_token(row["token_hash"])
        return json_response({})  # RFC 7009: 200 whether or not the token existed

    def explain_access_failure(self, token: str, resource: str) -> tuple[str, str | None]:
        """Why an access token was refused: (reason, client id). For the owner's log only; callers always get the same 401."""
        row = self.store.get_token(hash_token(token))
        if row is None:
            return "unknown (never issued here, or purged after it expired)", None
        if row["kind"] != "access":
            return "not an access token", None
        grant = self.store.get_grant(row["grant_id"])
        cid = grant["client_id"] if grant else None
        if row["expires_at"] <= time.time():
            return "expired", cid
        if grant is None or grant["revoked_at"] is not None:
            return "grant revoked", cid
        client = self.store.get_client(grant["client_id"])
        if client is None or client.revoked:
            return "client revoked", cid
        if not ct_equal(grant["resource"], resource):
            return "issued for another plugin", cid
        return "unknown", cid

    # -------------------------------------------------- resource-server checks
    def verify_access_token(self, token: str, resource: str) -> Principal | None:
        """The token must be active and bound to exactly this resource."""
        row = self.store.lookup_access(hash_token(token))
        if row is None or not ct_equal(row["resource"], resource):
            return None
        return Principal(row["client_id"], row["grant_id"], row["resource"])
