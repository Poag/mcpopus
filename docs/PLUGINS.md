# Writing a plugin

A plugin is a Python package in the plugins directory (`/plugins` in the container). It is loaded into the host
process, so it is trusted code (docs/SECURITY.md). The plugin name is the directory name, lower case, 1 to 32
characters of `a-z`, `0-9` and `-`, starting with a letter. It becomes the endpoint `https://<host>/<name>`.

```
plugins/notes/
  plugin.toml      manifest
  __init__.py      Config (optional), the Plugin class, setup(), teardown() (optional)
```

## Manifest

```toml
name = "notes"                 # must equal the directory name
version = "0.1.0"
description = "Plain-text notes."
min_host_version = "0.1.0"     # load is refused on an older host
```

## Worked example

This is `plugins/notes` in the repository; `tests/test_example_plugins.py` checks that it behaves as described.

```python
from mcpopus.plugin import BaseModel, Field, Plugin, PluginHost, ToolError, tool

class Config(BaseModel):
    max_notes: int = Field(100, ge=1, le=10_000, description="Refuse to create more notes than this")

class Notes(Plugin):
    @tool(tier="read")
    async def read_note(self, name: str) -> str:
        """Read one note."""
        ...

    @tool(tier="write")
    async def add_note(self, name: str, text: str) -> str:
        """Create or replace a note. Disabled until the owner enables it by name."""
        ...

async def setup(host: PluginHost) -> None:
    await host.add_plugin(Notes(host.context))
```

What happens:
- `setup(host)` must call `host.add_plugin()` exactly once. The `Plugin` instance is the cog analogue.
- Methods decorated with `@tool`, `@resource(uri)` or `@prompt()` become the MCP surface. Type hints give the
  input schema; the docstring is the description.
- Every tool states a **tier**: `read`, `write` or `admin`. A new plugin is read-only: write and admin tools are
  not served until the owner ticks them on the plugin's page in the admin UI (one tick box per tool; policy `enable_tools`).
- Return `str`, or anything JSON-serialisable (the host converts it to text and caps its size).
- Raise `ToolError("message")` for a failure the model should read. Any other exception is logged and the model sees
  only "The tool failed.", so internal detail and secrets do not leak.
- `teardown(host)` is optional. It runs on unload and on the old version after a reload. An exception in it is
  logged and ignored, as in discord.py.

## The context

`host.context` (also `self.ctx` in a `Plugin`) is the only thing the host hands over:

| Field | Meaning |
| --- | --- |
| `config` | the validated `Config` instance, or `None` if the plugin declares none |
| `data_dir` | a private directory, `/data/plugins/<name>/` |
| `logger` | `logging.Logger` named `mcpopus.plugin.<name>`; registered secrets are redacted from its output |
| `http` | an `httpx2.AsyncClient` (15 s timeout, no redirects followed, 10 connections) |
| `audit` | a callable that adds a line to the audit log (rarely needed: tool calls are audited for you) |
| `stats` | `ctx.stats.count("bytes_written", n)` adds to a named usage counter shown on the plugin's page (see Usage statistics). Absent on hosts older than 0.2.0: use `getattr(self.ctx, "stats", None)` |

## Arguments a tool does not declare

From host 0.2.0 a call that names an argument the tool does not declare is refused with an error that lists the names it accepts
(`Unknown argument 'folder' for tool list_messages. It accepts: mailbox, limit. ... Nothing was run.`), and the tool does not run. Before,
the extra argument was silently dropped and the tool ran with its default, which hid stale tool lists in clients after a plugin renamed a
parameter. The names from the caller are shown with only letters, digits, `_`, `.` and `-` (others become `?`), at most 40 characters and
three names, and the values are never echoed. The same applies to prompts. A parameter you rename or remove will therefore make old clients
fail loudly until they reload the tool list; keep old names working (accept both, one as an optional alias) if that matters.

Required arguments left out, and values of the wrong type, are still reported by the MCP SDK's own validation, whose message includes the
rejected value (see docs/SECURITY.md).

## Usage statistics

The host records every tool call for you: calls, failures, refused calls (policy or rate limit), time, the size of the arguments and
the size of the result, per day, plugin, client and tool. It never stores argument values or result content. The plugin's admin page shows
today and the last 7 days, a 14-day chart and a table per tool; the Home cards show today's calls and when each plugin was last used; the
Access page shows calls and last use per client. Days are UTC and 90 days are kept.

The Access page also lists the requesting agents of the last 30 days: the application (OAuth client), a short agent name taken from the `User-Agent` header, the MCP protocol version header, the plugin, the source address (and Cloudflare's country code when the proxy headers are trusted), request counts and first and last seen. These values come from the caller, so they are a display hint and never decide access. Addresses can be switched off with `MCPOPUS_STATS_RECORD_IP=false`; entries are kept for 90 days.

A plugin can add its own counters with `self.ctx.stats.count(name, amount)`, for example bytes written or notes deleted. Names are lower
case letters, digits and underscores (at most 40 characters), amounts must be zero or more, and each plugin may keep 20 distinct names.
Counters whose name starts with `bytes` are shown as sizes. Never count anything that identifies content.

## Config schema and secrets

Declare `Config` as a pydantic v2 model at module level. The admin UI renders a form from it, validates it,
stores it, and reloads the plugin. Field types map to inputs: `str`, `int`, `float`, `bool`, `Literal[...]` or an
enum (select), `list[str]` (one per line), `SecretStr` (password input). Anything else is a JSON text box.

```python
class Config(BaseModel):
    host: str = Field(description="IMAP server name")
    port: int = 993
    password: SecretStr            # a secret field
```

A `SecretStr` field is a secret: encrypted at rest (AES-256-GCM, key from outside the data directory), never shown
back in the UI (only "set" or "not set"), registered with the log redactor, and passed only to this plugin.
Read it with `self.ctx.config.password.get_secret_value()` at the moment of use. Never return it from a tool.
If the config is invalid, the plugin does not load and the error names the fields, never the values.

## Untrusted output

If a tool returns text from outside (mail, web pages), set `untrusted=True`. The host caps the size and wraps the
result in `<untrusted-data source="plugin.tool">` with a note that it is data, not instructions, and neutralises
an embedded closing tag. This reduces prompt-injection risk; it does not remove it. Keep write tools out of any
plugin that reads untrusted content where you can.

## Policy (set by the owner, enforced by the host)

Per plugin, on its admin page: one tick box per tool (read tools start ticked; write and admin tools start unticked), calls per minute
(default 60), output cap in bytes (default 64 KiB). Underneath this is stored as read-only (on until any write or admin tool is ticked),
enabled write and admin tools, and denied read tools. A tool the policy withholds is not listed and cannot be called.

## Installing from the admin UI

The **Plugins** page has a **Plugin sources** section. The default source is `https://github.com/Poag/mcpopus-plugins`; add more with
a public https URL and a branch or tag. A repository needs `plugins/<name>/plugin.toml` and `__init__.py` (the layout of this
documentation's examples). Steps: add or fetch a source, tick "I trust this code", press Install; the plugin loads and its settings
page is ready. Installed plugins run straight from the checkout under `/data/sources`, and a directory of the same name in the plugins
volume always takes priority.

Updates are never automatic. **Fetch updates** only downloads; the page then shows the new commits and changed files, and the plugin
keeps running the commit you applied until you press **Apply update** (which reloads it; if the new version fails to load the
old one keeps running). Only public repositories are supported (no credentials in the URL). This installs code that runs inside the
host, so read it first (the page links to the code on GitHub).

## Load, unload and reload

```bash
podman exec mcpopus mcpopus plugins list
podman exec mcpopus mcpopus plugins reload notes      # also: load, unload, enable, disable
```

The admin UI has the same buttons. A reload imports the new code under a fresh module name and runs `setup`
first. If that fails, for any reason, the old version keeps serving and the error is shown. Only on success is the
new version swapped in, requests already running on the old version get up to 5 seconds to finish, and then its
`teardown` runs. Consequences for plugin authors:
- For a moment two instances of the plugin exist. Do not hold exclusive locks that the new instance needs in `setup`.
- Clients connected through a session (the older protocol revision) must reconnect after a reload; their next call
  fails and a new connection works (observed, `tests/test_manager.py::test_legacy_session_after_reload`). Clients
  are not sent `tools/list_changed` by a reload.
- Module-level state is per version. Persist anything that matters in `data_dir`.
- Python caches nothing for plugins: bytecode writing is off in the host.

## Dependencies

The first version bundles a fixed set of libraries in the image and installs nothing at run time. A plugin may
import anything in `requirements.lock` (notably `httpx2`, `pydantic`, `cryptography`, `starlette`, `mcp`). To add
a library:

1. Add it to `dependencies` in `pyproject.toml` with an exact version, and use it from the plugin.
2. Regenerate the lock: `uv pip compile pyproject.toml --universal --generate-hashes -o requirements.lock`.
3. If it is imported lazily, add its top-level module to the list in `cmd_smoke` (`src/mcpopus/cli.py`) so CI imports it.
4. Commit; CI builds and smoke-tests the image for amd64 and arm64; pull the new image in Dockhand.

## Checklist before enabling a plugin

- Does every tool state the lowest tier that is true? Anything that changes state outside the plugin is `write`.
- Does any path, URL or query come from a tool argument? Validate it (see `_path` in `plugins/notes`).
- Can the output contain text written by someone else? Mark it `untrusted=True`.
- Does it log or return anything from `config`? It must not.
