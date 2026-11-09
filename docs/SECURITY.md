# Security

## Trust model, stated plainly

**Plugins run inside the host process and share its memory.** A plugin can read the host's keys, every other plugin's
data and secrets in memory, and the database. There is no sandbox. Therefore:

- Install only plugins you wrote or have read. Treat adding a plugin as adding code to the host.
- Third-party MCP servers do not belong in-process. Front them with the proxy plugin (planned), which talks to them over
  the network with its own credentials.
- The mitigations below limit accidents and the damage from a compromised *remote caller*. They are not a boundary
  against a malicious plugin.

## What is protected, and how

| Concern | Measure |
| --- | --- |
| Token for one plugin used on another | Opaque tokens are bound to one canonical resource URL (`https://host/<plugin>`) and compared exactly; also checked at authorisation, so no token can be minted for a resource that is not a loaded plugin |
| Unknown plugin vs bad credential | Same 401 body and headers for no token, bad token, another plugin's token and an unknown plugin; metadata is served for any well-formed name |
| Plugin names and paths | Names match `^[a-z][a-z0-9-]{0,31}$`, minus reserved words; the first path segment only; deeper paths are 404 after authentication; plugin directories with other names are ignored |
| Token theft from the database | Tokens, codes and session ids are stored as SHA-256 hashes (they carry 256 bits of randomness); client secrets likewise |
| Stolen refresh token | Rotation on every use; reuse of a rotated token revokes the whole grant; authorisation-code reuse revokes what was issued from it |
| Authorisation interception | PKCE with S256 only, exact redirect URI match (loopback ignores the port), `iss` returned, redirect URIs for dynamic registration limited by an allow-list |
| Password guessing | Argon2id; 5 failures per address and 20 overall per 15 minutes on each login, 5 per authorisation request; TOTP codes single-use; a missing credential costs the same as a wrong one; same page whichever factor failed |
| Admin takeover via the internet | Admin is a separate listener, never routed through Caddy or the tunnel; its own password and TOTP secret; Host allow-list; cookie `HttpOnly`, `SameSite=Strict`; CSRF token on every POST; GET never changes state |
| Secrets at rest | AES-256-GCM (`cryptography`), 96-bit random nonce, context bound as associated data, key supplied by environment variable or a file outside the data directory |
| Secrets in logs and output | `SecretStr` fields are registered with a log filter that replaces them in messages and tracebacks; tool errors are generic; the admin UI shows "set" or "not set" only; validation errors carry field names, never values |
| Prompt injection from tool output | Tools marked `untrusted` are size-capped and wrapped as data. This lowers risk; it does not remove it |
| Runaway or abusive use | Per-plugin rate limit and output cap; write tools off by default and enabled by name; deny list always wins |
| Clickjacking, XSS | Autoescaped templates, CSP `default-src 'none'`, `frame-ancestors 'none'`, `X-Frame-Options: DENY`; client names are sanitised and escaped |
| Container | Non-root user, read-only root filesystem, no capabilities, `no-new-privileges` (see `compose.yaml`) |
| Audit | JSON lines: plugin, tool, argument names, status, duration, size, client id. No argument values, no results |

## Plugin sources (installing from git)

Adding a source and installing a plugin is installing code into the host process (see the trust model above). Safeguards, none of which
replaces reading the code: https only, no credentials in URLs; each add, install and update needs an explicit confirmation tick; fetching
never changes what runs, and an update is reviewed (commit list and changed files) before it is applied; git runs without a shell and with
hooks, symlinks, prompts, system and user configuration and all non-https protocols disabled; at most 10 sources and 50 MB per repository; a
directory in the plugins volume overrides an installed plugin of the same name; admin-only (own login, CSRF). The host contacts whatever
host the admin names, which is an admin decision (it could reach internal addresses).

## Known limits and accepted risks

- **Authenticator set-up window.** Until the admin authenticator is set up in the admin UI (or supplied in `MCPOPUS_ADMIN_TOTP_SECRET`), the admin
  login is password-only and the first person to sign in enrols their device. Do it straight after the first start; the listener is internal.
  Connector sign-in is refused until its authenticator exists, so that window does not open the public side.

- **Lockout.** The global login limit means an attacker who keeps failing can stop the owner signing in for up to 15
  minutes at a time. The alternative, no global limit, lets a distributed guesser run unthrottled. Lockout does not
  open anything.
- **Dynamic client registration is open** (clients must use an allowed redirect URI, registration is rate-limited,
  and 200 registrations are retained; unused ones are pruned after a day). A registered client can do nothing without the
  owner's password and TOTP.
- **Rate limits are per process, in memory.** They reset on restart.
- **Refresh-token reuse detection** can revoke a grant when a client legitimately retries after a lost response; the owner
  signs in again.
- **Trusting proxy headers.** With `MCPOPUS_TRUST_PROXY_HEADERS=true`, the client address for rate limits comes from a request
  header. Enable it only if the public port cannot be reached except through Caddy.
- **The admin listener is plain HTTP**, and the compose file publishes it on all host interfaces. Keep the host's firewall and router from exposing it to the internet; use a trusted network, or put TLS in front.
- **No Origin check** on plugin endpoints: bearer tokens and the Host allow-list apply. Revisit if a browser client is used.
- **A compromised host process** (any plugin) holds the key and every secret.
- **CIMD (client ID metadata documents) is not supported**, deliberately: it makes the server fetch a URL named by an
  unauthenticated client.
- The OAuth code follows the MCP authorization specification and Claude's documentation; the RFC texts could not be fetched
  while building (docs/BUILD_LOG.md). A review against the RFCs is still due.

## Operating guidance

- Keep two different passwords of 14+ characters, each with its own authenticator entry.
- Keep `MCPOPUS_SECRET_KEY` outside the data volume and back it up separately.
- Revoke from the admin UI (Access) when a device is lost; revoking a client revokes all of its grants at once.
- Review the audit view after enabling any write tool.
- `podman logs mcpopus` shows failed logins and reuse events; none of it contains tokens or secrets.

## Reporting

This is a personal project. Send reports to the repository owner by private message rather than a public issue.

## Argument validation messages

Unknown argument names are refused by the host with a sanitised message (names only, bounded, no values). For wrong types and missing
required arguments the MCP SDK's validation error is returned to the same caller, and it quotes the offending input value
(for example `input_value='...'`). The caller supplied that value, so nothing new is disclosed to it, but a client that passes tool errors
on to a third party would also pass that value on. Plugins should not rely on argument validation to hide values.
