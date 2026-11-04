# Build log

Dated entries. "Verified" means I read the source named, on the date given. Anything not
verified is under "Unverified" and is written so that it is easy to change.

## 2026-11-04: phase 0 (spike)

### Verified

MCP Python SDK
- `pip index versions mcp`: 2.3.0 is the newest release; 1.30.0 is the newest 1.x. The SDK docs say v2 is the
  stable line and 1.x is in maintenance (https://py.sdk.modelcontextprotocol.io/whats-new/). I use **mcp 2.3.0**.
- v2 renamed `FastMCP` to `MCPServer` (`from mcp.server import MCPServer`), moved HTTP to `httpx2`
  (a Pydantic-maintained successor to httpx; metadata read from the installed wheel), and serves both the
  2025-11-25 and 2026-07-28 protocol revisions from one app (whats-new; run/legacy-clients).
- Streamable HTTP app: `MCPServer.streamable_http_app(streamable_http_path=...)` returns a Starlette app. A
  mounted sub-app's lifespan never runs, so each server's `session_manager.run()` must be entered by whoever
  hosts it (https://py.sdk.modelcontextprotocol.io/run/asgi/). My manager enters it in one task per plugin
  generation.
- The app arms DNS-rebinding protection for `localhost` only and answers 421 for any other Host unless given
  `transport_security=` (run/deploy). I disable the SDK check on plugin apps and enforce the Host allow-list in
  the gateway, before anything else runs.
- Auth hooks exist (`token_verifier=` plus `auth=AuthSettings(...)`, `validate_token_resource`; run/authorization).
  I do not use them: the gateway has to answer unknown plugin and bad token identically and serve the metadata
  itself. The SDK docs call the embedded `auth_server_provider=` legacy.
- Client: `Client(streamable_http_client(url, http_client=httpx2.AsyncClient(...)))`; bearer headers or
  `auth=OAuthClientProvider(...)` go on the httpx2 client (client/transports, client/oauth-clients). The same
  client can connect to a remote MCP URL, so a proxy plugin is feasible. **Re-exporting an upstream's tools from a
  server is not yet checked**; that is phase 3 work.
- Tool functions: `add_tool(fn, name=, description=, structured_output=)`. Only `ToolError` messages reach the
  model; other exceptions become a generic error. Handlers declared with a custom `__signature__` work
  (tested with `from __future__ import annotations` in a plugin).
- `list_changed`: in v2 notifications use `subscriptions/listen` on the 2026 path and are published with
  `ctx.notify_tools_changed()`; they are per server object. A reload replaces the server object, so connected
  clients are not notified; legacy sessions on the old object receive an unknown-session error on their next call
  and re-initialise. Not implemented; see decisions.

Claude connector behaviour (https://claude.com/docs/connectors/building/authentication.md and
https://claude.com/docs/connectors/custom/add-unlisted.md)
- A 401 with `WWW-Authenticate: Bearer resource_metadata="..."` is required; a header on a 200 is ignored.
- If the header lacks the pointer Claude probes `/.well-known/oauth-protected-resource/<mcp-path>` then
  `/.well-known/oauth-protected-resource` (matches the MCP spec text I fetched from the spec repository,
  `docs/specification/2025-11-25/basic/authorization.mdx`).
- The metadata `resource` must equal the URL the user typed, including any path. First entry of
  `authorization_servers` only.
- AS metadata at RFC 8414 or OIDC discovery paths. DCR (RFC 7591) is the default; CIMD only when the metadata
  advertises both `client_id_metadata_document_supported: true` and `none` in token auth methods. I advertise
  neither CIMD value, so Claude falls back to DCR.
- Hosted Claude callback: `https://claude.ai/api/mcp/auth_callback`. Claude Code: loopback on any port.
- `/token` must accept `application/x-www-form-urlencoded`; refresh failures must be `invalid_grant`; rotate
  refresh tokens for public clients. 10 s limit on discovery, registration and token; 30 s on refresh.
- Anthropic egress is `160.79.104.0/21`. A "custom connector" dialog offers: Claude's published identity (CIMD),
  register automatically (DCR), or your own client ID with optional secret.
- MCP spec: clients MUST send `resource` on authorization and token requests (spec text above). The SDK's own
  OAuth client does (tested: `tests/test_sdk_oauth_client.py`). **Whether claude.ai does is unverified.**

GitHub
- Arm64 hosted runner label `ubuntu-24.04-arm`
  (https://raw.githubusercontent.com/github/docs/main/data/reusables/actions/supported-github-runners.md and
  actions/runner-images README). Whether it is available for this repository's visibility is unverified.
- Latest major tags of the actions used were read with `git ls-remote --tags`: checkout v7, setup-python v7,
  setup-buildx v4, login v4, metadata v6, build-push v7, upload-artifact v7, download-artifact v8.
- `python:3.13-slim` has amd64 and arm64 manifests (Docker Hub API).

### Unverified (and where to change it)
- The RFC texts (7591, 7636, 7009, 8414, 8707, 9207, 9728) could not be fetched: rfc-editor.org, ietf.org and
  datatracker are blocked from this sandbox. I implemented from the MCP spec text, Claude's documentation and
  the SDK's own client and server code, and tested against the SDK's OAuth client. Re-read the RFCs before
  relying on edge cases (error codes for DCR in `oauth.register`, `invalid_target` handling in `oauth._resolve_resource`).
- OAuth 2.1 draft: not fetched; PKCE-always, S256-only, exact redirect matching and refresh rotation with reuse
  detection are taken from the MCP spec's references to it.
- Docker image build: no container daemon in this sandbox. The Dockerfile and compose.yaml have not been run
  here; CI is the first real build. Install from the hashed lock was tested in a clean Python 3.12.3 virtualenv.
- claude.ai behaviour: the whole of docs/SPIKE.md.

### Decisions
- mcp 2.3.0 over 1.30.0: current stable, serves both protocol eras, and 1.x is maintenance only.
- Own gateway rather than SDK auth: see above. Tokens are opaque, SHA-256 hashed in SQLite, bound to one
  canonical resource URL (`https://mcp.gany.net/<plugin>`); the check is exact string equality on that URL.
- Resource binding when `resource` is absent: the request is refused with `invalid_target`, unless the client was
  pre-registered and pinned to one plugin (`mcpopus client add --plugin hello`). The authorise and token
  endpoints log which parameter names arrive (never values) under `mcpopus.oauth.diag`, so the spike shows what
  Claude sends. The binding sits behind `routing.Routing`; `MCPOPUS_ROUTING=subdomain` switches to
  `https://<plugin>.<domain>` with per-host metadata (unit-tested only).
- Two credential realms: `oauth` (internet-facing login) and `admin` (internal listener). Different passwords
  and TOTP secrets, so compromise of the public login does not give access to plugin configuration.
- No login session on the public side: each authorisation needs password and a fresh TOTP code. TOTP codes are
  single-use (step must increase). Limits: 5 failures per client address and 20 overall per 15 minutes, 5 per
  authorisation request. The global limit can lock the owner out for up to 15 minutes under attack.
- Password hashing: Argon2id via argon2-cffi 25.1.0 defaults (RFC 9106 low-memory profile, per the library).
  TOTP is implemented in 40 lines on the standard library (HMAC-SHA1, 6 digits, 30 s) to avoid a dependency.
- Secrets at rest: AES-256-GCM from `cryptography`, 96-bit random nonce, context bound as associated data.
- DCR redirect URIs are allow-listed (default: the claude.ai callback and loopback). Change with
  `MCPOPUS_ALLOWED_REDIRECT_URIS`. If Claude reports a different callback, the rejected URI is in the log.
- No `Origin` check: bearer tokens and the Host allow-list cover the DNS-rebinding case; revisit if a browser client is used.
- Reload sets the new generation up before retiring the old one (differs from discord.py, which unloads first),
  so a failed reload never leaves a gap. Each generation imports under a unique module name.

### Lessons
- Test harness: single-use TOTP codes make repeated logins in one test fail; the fixture moves a fake clock one
  step per code.
- The SDK client validates `iss` on the authorisation response (RFC 9207). The server therefore returns `iss`
  and advertises `authorization_response_iss_parameter_supported`.

## 2026-11-04: phases 1 and 2 (plugin manager, admin UI, secret store)

### Verified by running (tests in `tests/`)
- Load, unload, reload, failure isolation: plugin raising in `setup`, at import, with a syntax error, with no
  `setup`, registering none or two plugins, duplicate tool names (teardown then runs to release resources),
  setup timeout, invalid config (error names fields, never values), manifest problems; raising in `teardown`
  (ignored on unload and on the old version of a reload); a failed reload leaves the old version serving, including
  to a client that was already connected; a later good reload clears the error; unrelated plugins keep serving
  through all of it; an in-flight call finishes before the old version is stopped.
- Legacy (session-based) client connected before a reload: its next call fails, a new connection works. List-changed
  is not sent. (`test_legacy_session_after_reload`.)
- Real process (`python -m mcpopus run`): health, the CLI over the unix control socket (list, load, unload, reload,
  enable, disable, a failing reload reported with exit status 1), traversal name refused, clean exit on SIGTERM.
- Policy: read-only by default; write tool served only when not read-only and named; allow and deny lists; rate limit;
  output cap; untrusted wrapping with embedded closing tag neutralised; resources and prompts; audit lines carry
  argument names, never values or results; secrets absent from logs (a plugin that logs its secret and one that
  raises with it), from tool output, from the admin pages and from `plugins.json`.
- Admin: separate listener, own credentials (the OAuth password is refused there), login rate limit, session cookie
  flags, CSRF on every POST, GET does not mutate, Host allow-list (rebinding), plugin control, config forms generated
  from the pydantic schema (validation errors, blank secret keeps stored value, clear secret), policy form, revoke
  grant/client (tokens and refresh then fail), pre-registered clients (secret shown once, hash stored, pin to a
  plugin enforced), audit view, markup escaped.
- TOTP matches the RFC 6238 SHA-1 vectors (vectors recalled from the RFC, not re-fetched).
- CI run 3 on GitHub: the `test` job passed on Python 3.12 from the hashed lock; both image builds (amd64 on
  `ubuntu-24.04`, arm64 on `ubuntu-24.04-arm`) succeeded and `mcpopus smoke` printed `smoke ok` inside the image.
  The container-run part of the smoke test failed on an invalid container name (fixed in a later commit; see the
  report for the latest run).

### Decisions
- Control plane for the CLI is a unix socket in `<data>/run` (directory 0700), served by a third uvicorn server in
  the same process. No network address, no token to manage; access means shell access to the container.
- `serve()` runs three uvicorn servers in one loop. uvicorn installs signal handlers per server, so a small
  subclass disables that and `serve()` handles SIGINT and SIGTERM once. This depends on uvicorn 0.54's
  `capture_signals` method (pinned); re-check on upgrade.
- Admin forms come from `Config.model_fields`; `SecretStr` is the marker for a secret field. A form is validated as
  a whole (including secrets left unchanged) before anything is stored; then the plugin is reloaded.
- Plugin code is imported with bytecode writing off, each generation under a unique module name.
- The policy is applied twice: tools it withholds are not registered, and the wrapper re-checks at call time.
- Admin sessions: 8 hours absolute, random id stored hashed, per-session CSRF token. The cookie is not `Secure` by
  default because the listener is plain HTTP on an internal address (setting available).

### Unverified
- The container itself has not been run here (no daemon). `compose.yaml` options (`read_only`, `cap_drop`, named
  volume ownership copied from the image) are untested on Podman. Test on the Pi.
- Caddy `flush_interval` advice and Cloudflare behaviour for event streams.
- Whether Claude's connector keeps working across reloads without re-adding (it should reconnect; untested with Claude).
- The `ubuntu-24.04-arm` runner worked for this repository; its availability depends on repository visibility and plan.

### Lessons
- `ToolError` text is prefixed by the SDK ("Error executing tool x: ..."); tests assert containment.
- A one-letter container name is invalid in Docker; CI found it on the first run.

## 2026-11-04: authenticator set-up in the admin UI

- QR codes use `segno` 1.6.6 (BSD-3, no dependencies; licence from its package classifier), rendered as inline SVG with a white
  background and quiet zone so it scans in dark mode. Added to `pyproject.toml`, the lock and the smoke import list.
- Tested: the page's SVG equals segno's output for the exact `otpauth://` URI shown. **Not scanned with a phone**: no QR decoder was run here.

## 2026-11-04: plugin sources (install from the admin UI)

- `src/mcpopus/sources.py`: git sources, fetch, review, apply, install. Default source seeded on first run only. Tested with local
  repositories (28 tests: URL and ref validation, install, restart, update review and apply, broken update keeps old version, shadowing by
  the plugins volume, symlinks not followed, markup escaped) and a real fetch of the default repository over https (found `obsidian` 0.1.0).
- Decisions: nothing automatic (fetch is separate from apply, apply from install); plugins load from the checkout through the manager's
  extra search path; manual plugin directory wins; public https repositories only (private repositories need a credential design first);
  `core.symlinks=false` makes repository symlinks plain files; git hooks and non-https protocols disabled; `git` added to the image.
- Unverified: the image with git on arm64 (CI builds it); behaviour through the Pi's network and Podman; very large or hostile repositories beyond the 50 MB check.
