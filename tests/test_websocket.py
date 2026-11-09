"""WebSockets for plugins: httpx2's AsyncClient.websocket needs wsproto, which the image must carry."""

import json

import httpx2
import uvicorn
from starlette.applications import Starlette
from starlette.routing import WebSocketRoute


async def echo(ws):
    await ws.accept()
    await ws.send_json({"type": "auth_required"})
    msg = json.loads(await ws.receive_text())
    await ws.send_json({"type": "result", "echo": msg})
    await ws.close()


async def test_httpx2_opens_a_websocket_to_a_local_server():
    import asyncio
    import socket

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(Starlette(routes=[WebSocketRoute("/api/websocket", echo)]), host="127.0.0.1", port=port, log_level="warning", lifespan="off"))
    task = asyncio.create_task(server.serve())
    for _ in range(200):
        if server.started:
            break
        await asyncio.sleep(0.02)
    try:
        async with httpx2.AsyncClient() as c:
            async with c.websocket(f"ws://127.0.0.1:{port}/api/websocket") as ws:
                assert (await ws.receive_json(timeout=5))["type"] == "auth_required"
                await ws.send_json({"id": 1, "type": "ping"})
                assert (await ws.receive_json(timeout=5)) == {"type": "result", "echo": {"id": 1, "type": "ping"}}
    finally:
        server.should_exit = True
        await asyncio.wait_for(task, 10)


def test_smoke_checks_the_websocket_dependency():
    import subprocess
    import sys

    out = subprocess.run([sys.executable, "-m", "mcpopus", "smoke"], capture_output=True, text=True, timeout=120)
    assert out.returncode == 0 and "smoke ok" in out.stdout, out.stderr[-500:]
