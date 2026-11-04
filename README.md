<p align="center"><img src="docs/assets/icon.svg" width="120" alt="MCP Octopus icon"></p>

<h1 align="center">MCP Octopus</h1>

<p align="center"><strong>One self-hosted MCP host. Many connectors. Each plugin on its own arm.</strong></p>

<p align="center">
<a href="https://github.com/Poag/mcpopus/actions/workflows/docker-publish.yml"><img alt="ci" src="https://github.com/Poag/mcpopus/actions/workflows/docker-publish.yml/badge.svg"></a>
<img alt="python" src="https://img.shields.io/badge/python-3.13-3776ab">
<img alt="arch" src="https://img.shields.io/badge/arch-amd64%20%7C%20arm64-555">
<img alt="image" src="https://img.shields.io/badge/image-ghcr.io%2Fpoag%2Fmcpopus-2496ed">
</p>

MCP Octopus runs a single process that serves several [MCP](https://modelcontextprotocol.io) endpoints, one per plugin
(`https://mcp.example.com/<plugin>`). Add each as its own custom connector in claude.ai. Plugins are installed from git
repositories in the admin UI and loaded, unloaded and reloaded at run time, so adding one never needs an image rebuild.

## Why

- **Your data stays yours.** Runs on your own hardware (it was built for a Raspberry Pi 4), behind your own reverse proxy.
- **One sign-in, scoped tokens.** A built-in OAuth 2.1 server for one owner (password plus authenticator code, PKCE S256, dynamic
  client registration, refresh rotation). A token is bound to one plugin and rejected on every other.
- **Safe by default.** Read-only until you say otherwise, tick-box tool policy, rate limits, output caps, audit log, secrets encrypted at rest.
- **Easy to run.** A Dockhand-style admin UI on a separate internal port: a Home page of plugin cards, plugin settings, sources, access, audit, and
  authenticator set-up with a QR code.
- **Extensible.** A plugin is a folder with a `plugin.toml` and a Python module. See [docs/PLUGINS.md](docs/PLUGINS.md).

```
claude.ai --> Cloudflare --> cloudflared --> Caddy --> :8080  /obsidian  /notes  /...
                                                      (admin UI on :8081, your network only)
```

## Get started

1. Deploy the image `ghcr.io/poag/mcpopus` with [`compose.yaml`](compose.yaml): [docs/DEPLOY.md](docs/DEPLOY.md).
2. Open the admin UI on port 8081, sign in, and scan the QR code to set up the authenticator.
3. **Plugins**, then **Fetch** on the default source, then **Install** a plugin (for example `obsidian`).
4. Add `https://<your host>/<plugin>` as a custom connector in claude.ai: [docs/SPIKE.md](docs/SPIKE.md).

A full worked example, from the first sign-in to Claude reading a note, is in the plugins repository:
[Set up Obsidian with Claude](https://github.com/Poag/mcpopus-plugins/blob/main/docs/GUIDE_CLAUDE.md).

## Plugins

Ready-made plugins live in [Poag/mcpopus-plugins](https://github.com/Poag/mcpopus-plugins), the default source in the admin UI.
Plugins run inside the host process and are trusted code: read what you install ([docs/SECURITY.md](docs/SECURITY.md)).

## Try it locally

```bash
python -m venv .venv && .venv/bin/pip install -e '.[dev]'
.venv/bin/python -m pytest
export MCPOPUS_PUBLIC_URL=http://127.0.0.1:8080 MCPOPUS_SECRET_KEY="$(.venv/bin/mcpopus genkey)" \
       MCPOPUS_DATA_DIR=./data MCPOPUS_CONFIG_DIR=./config MCPOPUS_PLUGINS_DIR=./plugins
.venv/bin/mcpopus init --realm oauth
.venv/bin/mcpopus run
```

## Documentation

| Guide | What is in it |
| --- | --- |
| [DEPLOY.md](docs/DEPLOY.md) | Dockhand, Caddy, cloudflared, keeping the admin listener internal, settings reference |
| [SPIKE.md](docs/SPIKE.md) | Connecting to claude.ai and what to report if it fails |
| [PLUGINS.md](docs/PLUGINS.md) | Writing a plugin, with a worked example (`plugins/notes`) |
| [SECURITY.md](docs/SECURITY.md) | Trust model, measures, accepted risks |
| [BUILD_LOG.md](docs/BUILD_LOG.md) | What was verified, decisions, lessons |

## Licence

[MIT](LICENSE). Plugins in [mcpopus-plugins](https://github.com/Poag/mcpopus-plugins) are MIT too; third-party notices are listed there.
