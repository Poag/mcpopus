"""Command line: mcpopus {genkey,init,run,client,...}."""

from __future__ import annotations

import argparse
import asyncio
import getpass
import logging
import os
import sys

from . import credentials
from .crypto import generate_key, hash_token, new_token
from .settings import Settings, SettingsError
from .store import Client, Store


def _settings() -> Settings:
    try:
        return Settings.from_env()
    except SettingsError as e:
        print(f"configuration error: {e}", file=sys.stderr)
        raise SystemExit(2) from None


def _read_password(realm: str) -> str:
    env = os.environ.get(f"MCPOPUS_INIT_{realm.upper()}_PASSWORD")
    if env:
        return env
    while True:
        pw = getpass.getpass(f"Set the {realm} password (min {credentials.MIN_PASSWORD_LENGTH} characters): ")
        problem = credentials.check_password_policy(pw)
        if problem:
            print(problem)
        elif pw != getpass.getpass("Repeat it: "):
            print("The passwords differ.")
        else:
            return pw


def cmd_totp(args: argparse.Namespace) -> int:
    secret = credentials.new_totp_secret()
    print(f"secret: {secret}")
    print(f"uri:    {credentials.provisioning_uri(secret, args.account)}")
    return 0


def cmd_genkey(args: argparse.Namespace) -> int:
    print(generate_key())
    return 0


def cmd_init(args: argparse.Namespace) -> int:
    s = _settings()
    store = Store(s.db_path)
    for realm in args.realms:
        if store.get_credential(realm) and not args.force:
            print(f"{realm}: already set (use --force to replace)")
            continue
        pw = _read_password(realm)
        problem = credentials.check_password_policy(pw)
        if problem:
            print(f"{realm}: {problem}", file=sys.stderr)
            return 1
        secret = credentials.new_totp_secret()
        store.set_credential(realm, credentials.hash_password(pw), s.secret_box.encrypt(secret, f"credential:{realm}:totp"))
        print(f"\n{realm}: password set. Add this to your authenticator app:")
        print(f"  secret: {secret}")
        print(f"  uri:    {credentials.provisioning_uri(secret, realm)}\n")
    return 0


def cmd_client(args: argparse.Namespace) -> int:
    s = _settings()
    store = Store(s.db_path)
    if args.action == "add":
        secret = None if args.public else new_token("cs")
        cid = new_token("c", 16)
        resource = None
        if args.plugin:
            from .routing import make_routing

            resource = make_routing(s.routing, s.public_url).resource_url(args.plugin)
        store.add_client(Client(cid, hash_token(secret) if secret else None, args.name, tuple(args.redirect_uri), "preregistered", resource, __import__("time").time(), False))
        print(f"client_id:     {cid}")
        print(f"client_secret: {secret or '(none: public client)'}  (shown once)")
        if resource:
            print(f"bound to:      {resource}")
    elif args.action == "list":
        for c in store.list_clients():
            print(f"{c.client_id}  {c.kind:13} {'REVOKED ' if c.revoked else ''}{c.name}  {c.resource or ''}")
    elif args.action == "revoke":
        print("revoked" if store.revoke_client(args.client_id) else "no such client")
    return 0


def cmd_plugins(args: argparse.Namespace) -> int:
    """Talks to the running host over its unix socket (inside the container, via podman exec)."""
    import httpx2

    s = _settings()
    transport = httpx2.HTTPTransport(uds=str(s.control_socket))
    try:
        with httpx2.Client(transport=transport, base_url="http://control", timeout=60) as c:
            if args.action == "list":
                r = c.get("/plugins")
                r.raise_for_status()
                for p in r.json():
                    err = f"  ! {p['error']}" if p.get("error") else ""
                    print(f"{p['name']:20} {p['status']:9} {p.get('version') or '-':8} tools={','.join(p['tools']) or '-'}{err}")
                return 0
            r = c.post(f"/plugins/{args.name}/{args.action}")
            body = r.json()
            if r.status_code != 200:
                print(f"{args.action} {args.name}: {body.get('error', r.status_code)}", file=sys.stderr)
                return 1
            print(f"{args.action} {args.name}: {body.get('status')}")
            return 0
    except httpx2.TransportError:
        print("cannot reach the running host (is it up, and are you in the same container?)", file=sys.stderr)
        return 1


def cmd_smoke(args: argparse.Namespace) -> int:
    """Import every module of the package and every declared dependency, then exercise
    the lazily used ones. Used by CI inside the built image."""
    import importlib
    import pkgutil

    import mcpopus

    for m in pkgutil.walk_packages(mcpopus.__path__, "mcpopus."):
        importlib.import_module(m.name)
    for dep in ("mcp", "starlette", "uvicorn", "pydantic", "cryptography", "argon2", "jinja2", "multipart", "httpx2", "segno"):
        importlib.import_module(dep)
    from .crypto import SecretBox, generate_key
    from .web import env as templates

    box = SecretBox.from_text(generate_key())
    assert box.decrypt(box.encrypt("x", "c"), "c") == "x"
    assert credentials.verify_password(credentials.hash_password("a-long-enough-password"), "a-long-enough-password")
    for t in ("authorize.html", "error.html", "base.html"):
        templates.get_template(t)
    import shutil

    assert shutil.which("git"), "git is needed to install plugins from sources"
    print("smoke ok")
    return 0


QUIET_LIBRARIES = ("httpx2", "httpcore2", "httpx", "httpcore", "mcp.server.streamable_http_manager", "mcp.server.mcpserver.server")


def configure_logging(level: str = "INFO") -> None:
    logging.basicConfig(level=getattr(logging, level), format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    # Libraries log routine traffic at INFO: every HTTP client request URL (a plugin may put a token in one), every MCP
    # session start and every tool error the model caused. Tool calls are in the audit log; at DEBUG all of it returns.
    for noisy in QUIET_LIBRARIES:
        logging.getLogger(noisy).setLevel(logging.DEBUG if level == "DEBUG" else logging.WARNING)


def cmd_healthcheck(args: argparse.Namespace) -> int:
    """Container health probe: exit 0 if the public listener answers /healthz. Needs no key or settings."""
    import os
    import urllib.request

    port = os.environ.get("MCPOPUS_PUBLIC_PORT", "8080") or "8080"
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))  # never through a proxy
    try:
        with opener.open(f"http://127.0.0.1:{port}/healthz", timeout=3) as r:
            return 0 if r.status == 200 else 1
    except Exception as e:  # noqa: BLE001
        print(f"unhealthy: {e}", file=sys.stderr)
        return 1


def cmd_run(args: argparse.Namespace) -> int:
    from .app import Host, serve

    s = _settings()
    configure_logging(s.log_level)
    asyncio.run(serve(Host.create(s)))
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="mcpopus")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("genkey", help="print a new secret key").set_defaults(fn=cmd_genkey)
    t = sub.add_parser("totp", help="generate a TOTP secret for MCPOPUS_*_TOTP_SECRET")
    t.add_argument("--account", default="mcpopus")
    t.set_defaults(fn=cmd_totp)
    i = sub.add_parser("init", help="set the owner (oauth) and admin passwords and TOTP secrets")
    i.add_argument("--realm", dest="realms", action="append", choices=["oauth", "admin"], default=None)
    i.add_argument("--force", action="store_true")
    i.set_defaults(fn=cmd_init)
    c = sub.add_parser("client", help="manage OAuth clients")
    c.add_argument("action", choices=["add", "list", "revoke"])
    c.add_argument("--name", default="Claude")
    c.add_argument("--redirect-uri", action="append", default=None)
    c.add_argument("--plugin", help="pin the client to one plugin")
    c.add_argument("--public", action="store_true", help="no client secret")
    c.add_argument("client_id", nargs="?")
    c.set_defaults(fn=cmd_client)
    sub.add_parser("healthcheck", help="exit 0 if the running host answers (container health probe)").set_defaults(fn=cmd_healthcheck)
    sub.add_parser("run", help="run the host").set_defaults(fn=cmd_run)
    pl = sub.add_parser("plugins", help="list, load, unload, reload, enable or disable plugins in the running host")
    pl.add_argument("action", choices=["list", "load", "unload", "reload", "enable", "disable"])
    pl.add_argument("name", nargs="?")
    pl.set_defaults(fn=cmd_plugins)
    sub.add_parser("smoke", help="import every module and dependency (CI)").set_defaults(fn=cmd_smoke)
    args = p.parse_args(argv)
    if args.cmd == "init" and not args.realms:
        args.realms = ["oauth", "admin"]
    if args.cmd == "plugins" and args.action != "list" and not args.name:
        p.error("plugin name required")
    if args.cmd == "client" and args.action == "add" and not args.redirect_uri:
        args.redirect_uri = ["https://claude.ai/api/mcp/auth_callback"]
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
