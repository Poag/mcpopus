# Deploying on a Raspberry Pi 4 (rootful Podman, Dockhand, Caddy, cloudflared)

Layout: `claude.ai` -> Cloudflare -> cloudflared -> Caddy -> mcpopus public listener (8080).
The admin listener (8081) is reached only from your own network.

The image is `ghcr.io/poag/mcpopus`, built by CI for amd64 and arm64 (the arm64 build runs on a native arm64
runner) and published from `main` (`latest`, short SHA) and from `vX.Y.Z` tags. `compose.yaml` only pulls it.

## 1. Prepare the host

Nothing to prepare on the host: plugins are installed from git repositories in the admin UI (section "Installing plugins"),
and they live in the data volume.

Generate the secret key once and keep it somewhere safe (password manager). Losing it makes stored plugin
secrets and the TOTP secrets unreadable; you would run `mcpopus init --force` and re-enter plugin secrets.

```bash
podman run --rm ghcr.io/poag/mcpopus:latest genkey
```

## 2. Create the stack in Dockhand

Make the values first (they are used once; keep them in a password manager):

```bash
podman run --rm ghcr.io/poag/mcpopus:latest genkey     # MCPOPUS_SECRET_KEY
```

Then use `compose.yaml` from the repository and set these in the stack's environment in Dockhand. The stack will not start if a
required one is missing. The authenticators are set up in the admin UI after the first start (step 3).

| Variable | Required | Value |
| --- | --- | --- |
| `MCPOPUS_PUBLIC_URL` | no | `https://mcp.example.com`, your public name (https, no path, no trailing slash) |
| `MCPOPUS_SECRET_KEY` | yes | the key from `genkey` |
| `MCPOPUS_ADMIN_PASSWORD` | yes | admin UI login password, 14+ characters |
| `MCPOPUS_OAUTH_PASSWORD` | yes | connector sign-in password; different from the admin one |
| `MCPOPUS_ADMIN_TOTP_SECRET`, `MCPOPUS_OAUTH_TOTP_SECRET` | no | authenticator secrets from `mcpopus totp`, if you would rather supply them than set them up in the admin UI |
| `MCPOPUS_ADMIN_ALLOWED_HOSTS` | no | hostnames you browse to the admin UI by (for example a Tailscale name), comma separated; otherwise it answers "Misdirected request". IP addresses always work |
| `MCPOPUS_TRUST_PROXY_HEADERS` | no | `true` only if the public port is reachable solely through Caddy, otherwise `false` (default) |

There is no username: each login is the password plus the current authenticator code. The environment is the source of
truth for what it sets: at every start the stored password (and a supplied authenticator secret) are made to match it, so
changing a password in Dockhand changes the login. An authenticator you set up in the admin UI is kept when the password changes.
The passwords are visible to anyone who can inspect the container, which is the same people who can read the key. If you
prefer not to keep them in the stack, leave all four unset and run `podman exec -it mcpopus mcpopus init` instead (and remove those lines from `compose.yaml`).

The key must never be in the data volume or the plugin directory. A file works too: mount it read-only elsewhere and set
`MCPOPUS_SECRET_KEY_FILE` instead (a key file inside the data directory is refused).

Volumes: `mcpopus-config` (`/config`: `plugins.json` with encrypted secrets), `mcpopus-data` (`/data`: SQLite database,
audit log, plugin data, installed plugins in `/data/sources`, control socket). The image also has an empty `/plugins`
directory; mount a folder there only if you want to drop in plugins by hand, which then take priority over installed ones.
The image's `/config` and `/data` are owned by uid 10001; if you use bind mounts instead of named volumes,
`chown 10001:10001` them.

## 3. First run

```bash
podman exec mcpopus mcpopus plugins list
```

Open the admin UI (port 8081, section 6) and sign in with the admin password only. This first sign-in goes straight to
**Set up the authenticator**: scan the QR code with your authenticator app (or enter the key by hand), type the code the app shows, and
confirm. Until you do, the admin login is password-only and nothing else in the UI is available, so do this straight after the
first start. From then on every sign-in needs the password and a code.

Then open **Sign-in** and set up the authenticator for the connector login the same way. Until you do, connector sign-in is
refused. (**Replace authenticator** on the same page re-keys either login if you change phone.) The page also shows the key and the `otpauth://` link
for apps that cannot scan.

## 4. Caddy

Add a site for the public name. mcpopus checks the `Host` header itself and rejects any name but the one in
`MCPOPUS_PUBLIC_URL`, so keep Caddy passing the original Host (its default).

```caddyfile
mcp.gany.net {
    reverse_proxy 127.0.0.1:8080
}
```

If Caddy runs as a container, attach it and mcpopus to one Podman network and use `reverse_proxy mcpopus:8080`;
then remove the `ports:` mapping for 8080. If you serve plain HTTP from Caddy to cloudflared (TLS ends at Cloudflare),
use `http://mcp.gany.net { ... }`. Do not add any route for the admin port.

Streaming: MCP responses may be long-lived event streams. If responses stall behind Caddy, add `flush_interval -1` inside
`reverse_proxy { ... }` (from Caddy's documentation as I remember it; not verified here, and not tested against Caddy).

## 5. cloudflared

Route the hostname `mcp.gany.net` to your Caddy origin, in the tunnel's public hostname list or `config.yml`
(`service: http://localhost:80`, or wherever Caddy listens). If you later switch to a subdomain per plugin
(`MCPOPUS_ROUTING=subdomain`) add a wildcard route for `*.mcp.gany.net` and a wildcard DNS record, and use
`*.mcp.gany.net` in Caddy.

Anthropic's requests come from `160.79.104.0/21`. If a Cloudflare WAF or bot rule blocks them, allow that range for this hostname.

## 6. Keep the admin listener internal

- `compose.yaml` publishes 8081 on every interface of the host (`"8081:8081"`), so it is reachable from your LAN or tailnet. It must
  not be reachable from the internet: do not forward it on the router, and put the host behind a firewall that only lets in what you intend.
  Its own login (password and authenticator), Host allow-list and CSRF protection stay on regardless. To limit it to one address, change the
  mapping to `"192.168.x.y:8081:8081"` or `"127.0.0.1:8081:8081"`.
- Do not create a Caddy site or a cloudflared route for it. Check from outside: `curl -s https://mcp.gany.net/login` must not
  return a login page, and port 8081 must not answer on the public address.
- The admin listener only accepts requests whose `Host` is `localhost`, an IP address, or a name in
  `MCPOPUS_ADMIN_ALLOWED_HOSTS` (comma separated), which defeats DNS rebinding.
- It speaks plain HTTP. If your LAN is not trusted, put it behind an internal TLS proxy and set `MCPOPUS_ADMIN_SECURE_COOKIE=true`.
- Alternative with no published port: `ssh -L 8081:127.0.0.1:8081 pi` and browse to `http://127.0.0.1:8081`.

## 7. Add a connector in claude.ai

See docs/SPIKE.md. Use `https://mcp.gany.net/<plugin>` as the server URL, one connector per plugin.

## Installing plugins from the admin UI

Open **Plugins** in the admin UI. Under **Plugin sources**, press **Fetch** on the default repository, then **Install** on a plugin
(tick the trust box). Add other public https repositories with **Add a source**. Installed plugins and their checkouts live in the data
volume (`/data/sources`), so no plugins folder is needed on the host. The container image includes `git` for it.

## High CPU

The host watches its own CPU. If the process stays above about 85% of one core for 30 seconds, it logs one WARNING from `mcpopus.diag`
with the stack of every thread, so the log names the function that is spinning (then it stays quiet for ten minutes). To take a snapshot
by hand at any time:

```bash
docker kill -s USR1 mcpopus     # prints every thread's stack to the container log (podman kill works the same)
```

Only code locations are logged, never arguments or secrets. Plugin threads appear as `asyncio_*` or `Thread-*` workers; the event loop is `MainThread`.

## After updating to 0.3.0

- Plugins can now list Python packages in `plugin.toml`; the host installs them into `/data/packages` when you add or update the plugin. The
  host needs outbound access to `pypi.org` and `files.pythonhosted.org` for that (or set `MCPOPUS_PIP_INDEX_URL` to a mirror). The install form
  lists the packages before you tick the trust box. The new image carries `pip` for this and no longer carries packages only plugins use
  (`wsproto`), so a plugin that needs one must list it in its `requirements`: until the plugins are updated, the Home Assistant registry reads and
  the SwarmUI live progress that need WebSockets will not work.

## After updating to 0.2.0

- 0.2.0 added `wsproto` to the image for WebSockets; 0.3.0 removes it again. A plugin that needs it lists `wsproto==1.3.2` in its own `requirements` (see 0.3.0 above).
- Tools now refuse arguments they do not declare. A client with an old tool list may get "Unknown argument ... reload it and try again".
  Disconnect and reconnect the connector in claude.ai (or refresh its tools) so it reads the current list.
- The plugin page shows the running version and when it was applied, and a rejected settings change or failed reload says so, with a time.

## Backups and updates

Back up `mcpopus-config`, `mcpopus-data` and the key. To update, pull the new image in Dockhand; the host loads plugins on
start. Plugins are loaded from the mounted directory, so adding one never needs an image.

## Settings reference

All are environment variables. Required: `MCPOPUS_PUBLIC_URL`, one of `MCPOPUS_SECRET_KEY` or `MCPOPUS_SECRET_KEY_FILE`. Credentials: `MCPOPUS_{ADMIN,OAUTH}_PASSWORD` and optionally `MCPOPUS_{ADMIN,OAUTH}_TOTP_SECRET`.

| Variable | Default | Meaning |
| --- | --- | --- |
| `MCPOPUS_ROUTING` | `path` | `path` or `subdomain` |
| `MCPOPUS_ALLOWED_REDIRECT_URIS` | `https://claude.ai/api/mcp/auth_callback,loopback` | comma separated; permitted for dynamic registration |
| `MCPOPUS_ACCESS_TOKEN_TTL` / `MCPOPUS_REFRESH_TOKEN_TTL` | `900` / `2592000` | seconds |
| `MCPOPUS_PUBLIC_BIND` / `_PORT` | `0.0.0.0` / `8080` | inside the container |
| `MCPOPUS_DEFAULT_SOURCE_URL` | `https://github.com/Poag/mcpopus-plugins` | the plugin source listed first on a new install (empty for none) |
| `MCPOPUS_ADMIN_BIND` / `_PORT` | `127.0.0.1` / `8081` (`0.0.0.0` in the image) | |
| `MCPOPUS_ADMIN_ALLOWED_HOSTS`, `MCPOPUS_ADMIN_SECURE_COOKIE` | empty, `false` | see above |
| `MCPOPUS_ALLOW_PACKAGE_INSTALL` | `true` | plugins may list Python packages in their manifest, which the host installs (wheels only) when the plugin is added or updated. `false` switches installing off; packages already installed still load |
| `MCPOPUS_PIP_INDEX_URL`, `MCPOPUS_PIP_FIND_LINKS` | empty | package index for those installs: empty is PyPI; `none` uses only the find-links location; or an http(s) or file URL for a mirror |
| `MCPOPUS_STATS_RECORD_IP` | `true` | keep the source address of each requesting agent in the statistics (the Access page). Behind Caddy it is the real address only when `MCPOPUS_TRUST_PROXY_HEADERS` is `true`; otherwise it is the proxy's. `false` stores none |
| `MCPOPUS_ADMIN_SESSION_IDLE_HOURS` | `168` | an admin session ends after this many hours without use (1 to 2160). Using the UI keeps it alive |
| `MCPOPUS_ADMIN_SESSION_MAX_DAYS` | `30` | the most a session can last in total, however often it is used (1 to 365) |
| `MCPOPUS_LOG_LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARNING` or `ERROR`. At `INFO` the log holds start-up, plugin load and unload, sign-ins, source changes and anything that failed; `DEBUG` adds OAuth request details and library noise |
| `MCPOPUS_ACCESS_LOG` | `false` | `true` prints one line per HTTP request (off by default; tool calls are in the audit log) |
| `MCPOPUS_TRUST_PROXY_HEADERS` | `false` | `true` or `false`; use `CF-Connecting-IP` or `X-Forwarded-For` for rate limits |
| `MCPOPUS_DATA_DIR`, `_CONFIG_DIR`, `_PLUGINS_DIR` | `/data`, `/config`, `/plugins` | |
