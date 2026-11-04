# Spike: add mcpopus to claude.ai as a custom connector

Goal: find out whether claude.ai can add a path-prefixed endpoint (`https://mcp.gany.net/hello`), register,
sign in, and call a tool. Nothing here is assumed to work. Report the checklist at the end.

## What was proven without Claude

Run locally (`pytest`): discovery documents, dynamic registration, authorisation with PKCE (S256 only), token
exchange, refresh rotation with reuse detection, a tool call through a real MCP client in both protocol
revisions, the MCP SDK's own OAuth client doing the whole dance, and a token for one plugin refused on another.

## 1. Run it

You need Python 3.12+ or the image. From a checkout:

```bash
python -m venv .venv && .venv/bin/pip install -e .
export MCPOPUS_PUBLIC_URL=https://mcp.gany.net
export MCPOPUS_SECRET_KEY="$(.venv/bin/mcpopus genkey)"      # keep this value; losing it loses stored secrets
export MCPOPUS_DATA_DIR=./data MCPOPUS_CONFIG_DIR=./config MCPOPUS_PLUGINS_DIR=./plugins
.venv/bin/mcpopus init --realm oauth                          # sets the sign-in password, prints a TOTP secret
.venv/bin/mcpopus run
```

Add the printed TOTP secret to an authenticator app. The password needs at least 14 characters.
With the container, use `compose.yaml` (docs/DEPLOY.md) and run `podman exec -it mcpopus mcpopus init --realm oauth`.

The `plugins/hello` directory in the repository is the plugin to serve. Copy it to the plugins directory.

## 2. Publish it

Caddy site `mcp.gany.net` reverse-proxying to the public listener (port 8080), and the existing cloudflared
route for `mcp.gany.net` pointing at Caddy. Check from outside:

```bash
curl -si https://mcp.gany.net/healthz
curl -si -X POST https://mcp.gany.net/hello          # expect 401 with WWW-Authenticate: Bearer resource_metadata="https://mcp.gany.net/.well-known/oauth-protected-resource/hello"
curl -s https://mcp.gany.net/.well-known/oauth-protected-resource/hello
curl -s https://mcp.gany.net/.well-known/oauth-authorization-server
```

Anthropic's requests come from `160.79.104.0/21`. If Cloudflare bot or WAF rules sit in front of
`mcp.gany.net`, they could block them (not verified); allow that range if the connector cannot reach the server.

## 3. Add the connector in claude.ai

Customize > Connectors > Add custom connector.

- Name: `mcpopus hello`
- Server URL: `https://mcp.gany.net/hello` (no trailing slash)
- OAuth client: try **Register automatically** first (dynamic client registration).

Then Connect. A browser window opens on `https://mcp.gany.net/oauth/authorize` showing "hello" as the
connector. Enter the password and the current code, Approve. Then, in a chat, enable the connector and ask Claude
to call `say_hello`.

Optional second attempts, in separate connectors, each with a fresh run:
- **Use your own OAuth client**: create one with
  `mcpopus client add --name claude --plugin hello`, enter the printed client ID (and secret) in the dialog.
- **Use Claude's published identity** (CIMD): mcpopus does not support it and does not advertise it, so Claude
  should fall back to registration. Note what happens.

## 4. What to observe

The host logs, at `MCPOPUS_LOG_LEVEL=DEBUG` (and `MCPOPUS_ACCESS_LOG=true` for the request lines), exactly what Claude sends (parameter names only, never values or tokens). Collect
the lines containing these names from the container log (`podman logs mcpopus`):

| Log name | Tells us |
| --- | --- |
| `mcpopus.gateway` `401 ... token_presented=False` | Claude reached the endpoint |
| `mcpopus.gateway` `metadata request for hello` | Which metadata URL Claude fetched (path-based or not). Also read the uvicorn access lines for `/.well-known/` |
| `mcpopus.oauth.diag` `dcr request keys=[...]` | What Claude registers with. A line `dcr rejected redirect_uri` means the callback differs from the allow-list |
| `mcpopus.oauth.diag` `authorize params=[...]` | Whether `resource` is sent |
| `mcpopus.oauth.diag` `token grant_type=... params=[...]` | Whether `resource` is sent on the token request; refresh requests appear later |

## 5. Report back

- [ ] Claude accepted the URL `https://mcp.gany.net/hello` and showed the sign-in (or the exact error text)
- [ ] Metadata URL(s) requested (paste the access-log lines for `/.well-known/`)
- [ ] Registration succeeded (DCR) / own client ID worked / CIMD fell back
- [ ] Parameter names on the authorise request (is `resource` there? what value?)
- [ ] Parameter names on the token request
- [ ] Redirect URI Claude used (shown on the consent page under "Returns to")
- [ ] Consent page shows `hello` and the client name
- [ ] `say_hello` returned `Hello, <name>!` in a chat
- [ ] The connector still worked after more than 15 minutes (a refresh happened; look for `grant_type=refresh_token`)
- [ ] Anything that failed, with the log lines around it

If `resource` is missing from Claude's requests, do not loosen the server. Send the log lines: the options are
a client pinned to one plugin (already supported for pre-registered clients) or a subdomain per plugin
(`MCPOPUS_ROUTING=subdomain`, needs a wildcard DNS and tunnel route, `*.mcp.gany.net`).
