from __future__ import annotations

import asyncio
import contextlib
import re
import shutil
import socket
import time
import types
from dataclasses import dataclass, field
from pathlib import Path

import httpx2
import pytest
import uvicorn

from mcpopus import credentials
from mcpopus.app import Host, build_public_app
from mcpopus.crypto import generate_key
from mcpopus.settings import Settings, SecretBox

ROOT = Path(__file__).resolve().parent.parent
PASSWORD = "correct horse battery staple"
ADMIN_PASSWORD = "another long admin passphrase"


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@dataclass
class Running:
    host: Host
    settings: Settings
    base: str
    server: uvicorn.Server
    totp_secret: str
    clock: types.SimpleNamespace
    plugins_dir: Path
    admin_base: str = ""
    admin_secret: str = ""
    admin_server: uvicorn.Server | None = None

    def admin_totp(self) -> str:
        self.clock.offset += credentials.TOTP_PERIOD
        return credentials.totp_at(self.admin_secret, time.time() + self.clock.offset)

    @contextlib.asynccontextmanager
    async def admin(self):
        """A signed-in admin client and its CSRF token."""
        async with httpx2.AsyncClient(base_url=self.admin_base, timeout=10, follow_redirects=False) as c:
            r = await c.post("/login", data={"password": ADMIN_PASSWORD, "totp": self.admin_totp()})
            assert r.status_code == 303, r.text
            page = await c.get("/")
            yield c, re.search(r'name="csrf" value="([^"]+)"', page.text).group(1)

    def totp(self) -> str:
        """A fresh code that has not been used: advances the fake clock one step each call."""
        self.clock.offset += credentials.TOTP_PERIOD
        return credentials.totp_at(self.totp_secret, time.time() + self.clock.offset)

    def client(self, **kw) -> httpx2.AsyncClient:
        return httpx2.AsyncClient(base_url=self.base, timeout=10, follow_redirects=False, **kw)


def make_plugin(plugins_dir: Path, name: str, init_py: str, version: str = "0.1.0", extra_toml: str = "") -> Path:
    d = plugins_dir / name
    d.mkdir(parents=True, exist_ok=True)
    (d / "plugin.toml").write_text(
        f'name = "{name}"\nversion = "{version}"\ndescription = "test plugin {name}"\nmin_host_version = "0.1.0"\n{extra_toml}'
    )
    (d / "__init__.py").write_text(init_py)
    return d


@pytest.fixture
async def running(tmp_path, monkeypatch):
    plugins = tmp_path / "plugins"
    plugins.mkdir()
    shutil.copytree(ROOT / "plugins" / "hello", plugins / "hello")
    port = free_port()
    base = f"http://127.0.0.1:{port}"
    key = generate_key()
    settings = Settings(
        public_url=base, data_dir=tmp_path / "data", config_dir=tmp_path / "config", plugins_dir=plugins,
        secret_box=SecretBox.from_text(key), public_bind="127.0.0.1", public_port=port,
        admin_bind="127.0.0.1", admin_port=free_port(),
    )
    host = Host.create(settings)
    secret = credentials.new_totp_secret()
    host.store.set_credential("oauth", credentials.hash_password(PASSWORD), settings.secret_box.encrypt(secret, "credential:oauth:totp"))
    clock = types.SimpleNamespace(offset=0.0)
    real_time = time.time
    monkeypatch.setattr(credentials, "time", types.SimpleNamespace(time=lambda: real_time() + clock.offset))
    admin_secret = credentials.new_totp_secret()
    host.store.set_credential("admin", credentials.hash_password(ADMIN_PASSWORD), settings.secret_box.encrypt(admin_secret, "credential:admin:totp"))
    from mcpopus.admin import build_admin_app

    server = uvicorn.Server(uvicorn.Config(build_public_app(host), host="127.0.0.1", port=port, log_level="warning", lifespan="on"))
    admin_server = uvicorn.Server(uvicorn.Config(build_admin_app(host), host="127.0.0.1", port=settings.admin_port, log_level="warning", lifespan="off"))
    tasks = [asyncio.create_task(server.serve()), asyncio.create_task(admin_server.serve())]
    for _ in range(200):
        if server.started and admin_server.started:
            break
        await asyncio.sleep(0.05)
    assert server.started and admin_server.started, "servers did not start"
    r = Running(host, settings, base, server, secret, clock, plugins, f"http://127.0.0.1:{settings.admin_port}", admin_secret, admin_server)
    yield r
    server.should_exit = admin_server.should_exit = True
    await asyncio.wait_for(asyncio.gather(*tasks), 20)
    host.store.close()
