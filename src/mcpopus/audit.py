"""Audit log (JSON lines) and secret-aware log redaction."""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from pathlib import Path
from typing import Any


class AuditLog:
    """Appends one JSON object per tool call. Argument *names* are recorded, never
    values; result content is not recorded. Rotates at max_bytes, keeping `keep` files."""

    def __init__(self, path: Path, max_bytes: int = 10 * 1024 * 1024, keep: int = 5) -> None:
        self.path, self.max_bytes, self.keep = path, max_bytes, keep
        self._lock = threading.Lock()
        path.parent.mkdir(parents=True, exist_ok=True)

    def _rotate(self) -> None:
        for i in range(self.keep - 1, 0, -1):
            src = self.path.with_name(f"{self.path.name}.{i}")
            if src.exists():
                os.replace(src, self.path.with_name(f"{self.path.name}.{i + 1}"))
        os.replace(self.path, self.path.with_name(f"{self.path.name}.1"))

    def record(self, *, plugin: str, tool: str, args: list[str], status: str, duration_ms: float, size: int,
               client_id: str | None = None, **extra: Any) -> None:
        entry = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "plugin": plugin, "tool": tool,
            "arg_names": sorted(args), "status": status, "duration_ms": round(duration_ms, 1), "size": size,
        }
        if client_id:
            entry["client_id"] = client_id
        entry.update(extra)
        line = json.dumps(entry, separators=(",", ":")) + "\n"
        with self._lock:
            try:
                if self.path.exists() and self.path.stat().st_size + len(line) > self.max_bytes:
                    self._rotate()
                fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
                with os.fdopen(fd, "a") as f:
                    f.write(line)
            except OSError:
                logging.getLogger("mcpopus.audit").error("cannot write audit log")

    def tail(self, n: int = 200) -> list[dict]:
        try:
            lines = self.path.read_text().splitlines()[-n:]
        except OSError:
            return []
        out = []
        for line in lines:
            try:
                out.append(json.loads(line))
            except ValueError:
                continue
        return out[::-1]


class RedactingFilter(logging.Filter):
    """Replaces registered secret values wherever they appear in a log record."""

    def __init__(self) -> None:
        super().__init__()
        self._secrets: dict[str, set[str]] = {}
        self._flat: list[str] = []

    def register(self, owner: str, values: list[str]) -> None:
        self._secrets[owner] = {v for v in values if v and len(v) >= 4}
        self._rebuild()

    def unregister(self, owner: str) -> None:
        self._secrets.pop(owner, None)
        self._rebuild()

    def _rebuild(self) -> None:
        self._flat = sorted({v for s in self._secrets.values() for v in s}, key=len, reverse=True)

    def redact(self, text: str) -> str:
        for v in self._flat:
            text = text.replace(v, "[redacted]")
        return text

    def filter(self, record: logging.LogRecord) -> bool:
        if self._flat:
            msg = self.redact(record.getMessage())
            record.msg, record.args = msg, None
            if record.exc_info:
                import traceback

                record.exc_text = self.redact("".join(traceback.format_exception(*record.exc_info)))
        return True


redactor = RedactingFilter()


def install_log_redaction() -> None:
    """Attach the redactor to the root handlers (so every logger is covered)."""
    root = logging.getLogger()
    for h in root.handlers:
        if redactor not in h.filters:
            h.addFilter(redactor)
