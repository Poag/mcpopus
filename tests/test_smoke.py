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
