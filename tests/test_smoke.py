"""The smoke command CI runs inside the image: every module and every direct dependency imports."""

import subprocess
import sys


def test_smoke_passes():
    out = subprocess.run([sys.executable, "-m", "mcpopus", "smoke"], capture_output=True, text=True, timeout=120)
    assert out.returncode == 0 and "smoke ok" in out.stdout, out.stderr[-500:]


def test_the_host_carries_no_plugin_only_packages():
    """wsproto (WebSockets) is for plugins that ask for it in their manifest; the host itself does not need it."""
    import tomllib
    from pathlib import Path

    deps = tomllib.loads((Path(__file__).parent.parent / "pyproject.toml").read_text())["project"]["dependencies"]
    names = {d.split("==")[0] for d in deps}
    assert names == {"mcp", "starlette", "uvicorn", "pydantic", "cryptography", "argon2-cffi", "jinja2", "httpx2", "pip", "segno"}


def test_importing_the_cli_does_not_load_the_heavy_libraries():
    """The container health check runs `mcpopus healthcheck` every 30 seconds; it must stay cheap on a Raspberry Pi."""
    code = ("import sys, mcpopus.cli as c; heavy = [m for m in ('cryptography', 'argon2', 'mcp', 'pydantic', 'starlette', 'jinja2', 'uvicorn') if m in sys.modules];"
            " print(heavy); sys.exit(1 if heavy else 0)")
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, out.stdout
