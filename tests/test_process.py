"""Run the real process (python -m mcpopus run): health, CLI over the control socket, clean shutdown."""

import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

from mcpopus.crypto import generate_key

from .conftest import ROOT, free_port, make_plugin


def run_cli(env, *args, timeout=30):
    return subprocess.run([sys.executable, "-m", "mcpopus", *args], env=env, capture_output=True, text=True, timeout=timeout)


def test_process_cli_control_socket_and_shutdown():
    tmp = Path(tempfile.mkdtemp(prefix="mo"))
    plugins = tmp / "plugins"
    plugins.mkdir()
    (plugins / "hello").symlink_to(ROOT / "plugins" / "hello")
    make_plugin(plugins, "alpha", "from mcpopus.plugin import Plugin, tool\nclass P(Plugin):\n    @tool(tier='read')\n    async def t(self) -> str: return 'x'\nasync def setup(host): await host.add_plugin(P(host.context))\n")
    port = free_port()
    env = {**os.environ, "MCPOPUS_PUBLIC_URL": f"http://127.0.0.1:{port}", "MCPOPUS_SECRET_KEY": generate_key(),
           "MCPOPUS_DATA_DIR": str(tmp / "d"), "MCPOPUS_CONFIG_DIR": str(tmp / "c"), "MCPOPUS_PLUGINS_DIR": str(plugins),
           "MCPOPUS_PUBLIC_BIND": "127.0.0.1", "MCPOPUS_PUBLIC_PORT": str(port)}
    proc = subprocess.Popen([sys.executable, "-m", "mcpopus", "run"], env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        for _ in range(100):
            try:
                assert json.load(urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=1)) == {"status": "ok"}
                break
            except OSError:
                time.sleep(0.1)
        else:
            raise AssertionError("did not start")
        out = run_cli(env, "plugins", "list").stdout
        assert "hello" in out and "alpha" in out and out.count("loaded") >= 2
        assert run_cli(env, "plugins", "unload", "alpha").returncode == 0
        assert "unloaded" in run_cli(env, "plugins", "list").stdout
        assert run_cli(env, "plugins", "unload", "alpha").returncode == 1  # not loaded: reported, not crashed
        assert run_cli(env, "plugins", "reload", "alpha").returncode == 0
        assert run_cli(env, "plugins", "reload", "hello").returncode == 0
        (plugins / "alpha" / "__init__.py").write_text("raise RuntimeError('broken')\n")
        bad = run_cli(env, "plugins", "reload", "alpha")
        assert bad.returncode == 1 and "import failed" in bad.stderr
        assert "alpha" in run_cli(env, "plugins", "list").stdout and "previous version" in run_cli(env, "plugins", "list").stdout
        assert run_cli(env, "plugins", "disable", "alpha").returncode == 0
        assert "disabled" in run_cli(env, "plugins", "list").stdout
        assert run_cli(env, "plugins", "load", "../etc").returncode == 1
        sock = tmp / "d" / "run" / "control.sock"
        assert oct(sock.stat().st_mode & 0o777) == "0o600" or oct(sock.parent.stat().st_mode & 0o777) == "0o700"
        proc.send_signal(signal.SIGTERM)
        assert proc.wait(timeout=20) == 0
        out = proc.stdout.read() or ""
        after_expected = out.rsplit("RuntimeError: broken", 1)[-1]  # the one deliberate traceback
        assert "Traceback" not in after_expected
    finally:
        if proc.poll() is None:
            proc.kill()


def test_healthcheck_command_fails_when_nothing_listens(monkeypatch):
    from mcpopus.cli import main

    monkeypatch.setenv("MCPOPUS_PUBLIC_PORT", "1")
    assert main(["healthcheck"]) == 1
