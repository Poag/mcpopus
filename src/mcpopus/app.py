"""Application assembly and process entry (public listener, admin listener, control socket)."""

from __future__ import annotations

import asyncio
import logging
import os
import signal
import stat
from collections.abc import Iterator
from contextlib import asynccontextmanager, contextmanager
from dataclasses import asdict, dataclass

import uvicorn
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route

from . import __version__
from .audit import AuditLog, install_log_redaction
from .manager import PluginLoadError, PluginManager
from .gateway import Gateway
from .oauth import OAuthServer
from .pluginconfig import ConfigStore
from .routing import Routing, make_routing, valid_plugin_name
from .crypto import SecretError
from .settings import Settings, SettingsError
from .sources import Sources
from .stats import Stats
from .store import Store

log = logging.getLogger("mcpopus")


@dataclass
class Host:
    settings: Settings
    store: Store
    routing: Routing
    audit: AuditLog
    configs: ConfigStore
    manager: PluginManager
    oauth: OAuthServer
    sources: Sources
    stats: Stats

    @classmethod
    def create(cls, settings: Settings) -> Host:
        for d in (settings.data_dir, settings.config_dir):
            d.mkdir(parents=True, exist_ok=True)
        store = Store(settings.db_path)
        apply_env_credentials(settings, store)
        routing = make_routing(settings.routing, settings.public_url)
        audit = AuditLog(settings.audit_path)
        configs = ConfigStore(settings.config_dir, settings.secret_box)
        sources = Sources(settings.config_dir, settings.data_dir, settings.default_source_url)
        stats = Stats(store)
        manager = PluginManager(settings.plugins_dir, settings.data_dir, configs, audit, sources.installed_paths, stats=stats)
        oauth = OAuthServer(settings, store, routing, manager.is_loaded)
        return cls(settings, store, routing, audit, configs, manager, oauth, sources, stats)


def apply_env_credentials(settings: Settings, store: Store) -> None:
    """If MCPOPUS_{OAUTH,ADMIN}_PASSWORD and _TOTP_SECRET are set, make the stored credential match them.
    The environment is then the source of truth, so changing it in the compose stack changes the login."""
    from . import credentials

    for realm, password, secret in (("oauth", settings.oauth_password, settings.oauth_totp_secret),
                                    ("admin", settings.admin_password, settings.admin_totp_secret)):
        name = f"MCPOPUS_{realm.upper()}"
        if password is None and secret is None:
            continue
        if password is None:
            raise SettingsError(f"{name}_TOTP_SECRET needs {name}_PASSWORD")
        problem = credentials.check_password_policy(password)
        if problem:
            raise SettingsError(f"{name}_PASSWORD: {problem}")
        if secret is not None and not credentials.valid_totp_secret(secret):
            raise SettingsError(f"{name}_TOTP_SECRET must be a base32 secret (generate one with 'mcpopus totp')")
        row = store.get_credential(realm)
        box = settings.secret_box
        if row is None:  # no TOTP secret given: it is set up in the admin UI
            store.set_credential(realm, credentials.hash_password(password), box.encrypt(secret, f"credential:{realm}:totp") if secret else "")
            log.info("%s credentials created from the environment", realm)
            continue
        if not credentials.verify_password(row["password_hash"], password):
            store.set_password(realm, credentials.hash_password(password))
            log.info("%s password updated from the environment", realm)
        if secret is not None:
            try:
                same = row["totp_secret_enc"] != "" and box.decrypt(row["totp_secret_enc"], f"credential:{realm}:totp") == secret
            except SecretError:
                same = False
            if not same:
                store.set_totp(realm, box.encrypt(secret, f"credential:{realm}:totp"))
                log.info("%s authenticator secret set from the environment", realm)


def build_public_app(host: Host) -> Starlette:
    async def healthz(request):  # no plugin information on the public listener
        return JSONResponse({"status": "ok"})

    @asynccontextmanager
    async def lifespan(app: Starlette):
        install_log_redaction()
        await host.manager.start()

        async def housekeeping() -> None:
            while True:
                host.store.purge_expired()
                host.stats.prune()
                await asyncio.sleep(600)

        janitor = asyncio.create_task(housekeeping())
        try:
            yield
        finally:
            janitor.cancel()
            await host.manager.stop()

    gateway = Gateway(host.routing, host.oauth, host.manager)
    routes = [Route("/healthz", healthz), *host.oauth.routes(), Route("/{path:path}", gateway, methods=["GET", "POST", "DELETE", "OPTIONS", "HEAD"])]
    return Starlette(routes=routes, lifespan=lifespan)


def build_control_app(host: Host) -> Starlette:
    """Management API for the CLI. Served on a unix socket (mode 0600 in a 0700 directory);
    it is never bound to a network address."""

    async def list_plugins(request):
        return JSONResponse([asdict(st) | {"loaded": host.manager.is_loaded(st.name)} for st in host.manager.status()])

    async def act(request):
        name, action = request.path_params["name"], request.path_params["action"]
        if not valid_plugin_name(name) or action not in ("load", "unload", "reload", "enable", "disable"):
            return JSONResponse({"error": "not found"}, 404)
        try:
            if action in ("enable", "disable"):
                host.configs.save(name, enabled=action == "enable")
                if action == "enable" and not host.manager.is_loaded(name):
                    st = await host.manager.load(name)
                elif action == "disable" and host.manager.is_loaded(name):
                    st = await host.manager.unload(name)
                else:
                    st = host.manager.states.get(name)
                if action == "disable" and st is not None:
                    st.status = "disabled"
            else:
                st = await getattr(host.manager, action)(name)
        except PluginLoadError as e:
            return JSONResponse({"error": str(e)}, 409)
        return JSONResponse(asdict(st) if st else {"name": name})

    return Starlette(routes=[
        Route("/plugins", list_plugins, methods=["GET"]),
        Route("/plugins/{name}/{action}", act, methods=["POST"]),
    ])


class _Server(uvicorn.Server):
    """uvicorn.Server without its own signal handling: serve() runs several servers
    in one process, and signals are handled once in serve(). Relies on uvicorn 0.54's
    capture_signals hook (pinned)."""

    @contextmanager
    def capture_signals(self) -> Iterator[None]:
        yield


async def serve(host: Host) -> None:
    s = host.settings
    # uvicorn sets its loggers from the last Config built, so every server gets the same level. Per-request access lines
    # are off unless MCPOPUS_ACCESS_LOG=true (they need the info level).
    uv_level = "info" if s.access_log else "warning"
    servers = [_Server(uvicorn.Config(
        build_public_app(host), host=s.public_bind, port=s.public_port, log_level=uv_level, access_log=s.access_log,
        proxy_headers=s.trust_proxy_headers, forwarded_allow_ips="*" if s.trust_proxy_headers else None,
        server_header=False, date_header=False,
    ))]
    sock = s.control_socket
    sock.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(sock.parent, 0o700)
    if sock.exists() and stat.S_ISSOCK(sock.stat().st_mode):
        sock.unlink()
    servers.append(_Server(uvicorn.Config(build_control_app(host), uds=str(sock), log_level=uv_level, access_log=False, lifespan="off")))
    from .admin import build_admin_app

    servers.append(_Server(uvicorn.Config(
        build_admin_app(host, s.admin_allowed_hosts, s.admin_secure_cookie), host=s.admin_bind, port=s.admin_port,
        log_level=uv_level, access_log=s.access_log, lifespan="off", server_header=False, date_header=False,
    )))
    log.info("mcpopus %s: public listener %s:%d for %s; admin listener %s:%d (publish internally only, never through the tunnel)",
             __version__, s.public_bind, s.public_port, s.public_host, s.admin_bind, s.admin_port)
    loop = asyncio.get_running_loop()

    def stop() -> None:
        for srv in servers:
            srv.should_exit = True

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop)
    tasks = [asyncio.create_task(srv.serve()) for srv in servers]
    try:
        await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    finally:
        stop()
        await asyncio.gather(*tasks, return_exceptions=True)
        host.store.close()
