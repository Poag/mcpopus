"""In-memory sliding-window rate limiter (single process)."""

from __future__ import annotations

import time
from collections import deque


class RateLimiter:
    def __init__(self, max_events: int, window_seconds: float, max_keys: int = 4096) -> None:
        self.max_events = max_events
        self.window = window_seconds
        self.max_keys = max_keys
        self._events: dict[str, deque[float]] = {}

    def _prune(self, key: str, now: float) -> deque[float]:
        q = self._events.setdefault(key, deque())
        while q and q[0] <= now - self.window:
            q.popleft()
        if len(self._events) > self.max_keys:
            for k in [k for k, v in self._events.items() if not v or v[-1] <= now - self.window]:
                del self._events[k]
        return q

    def blocked(self, key: str, now: float | None = None) -> bool:
        """True if the key is already at its limit (does not record an event)."""
        now = time.monotonic() if now is None else now
        return len(self._prune(key, now)) >= self.max_events

    def record(self, key: str, now: float | None = None) -> None:
        now = time.monotonic() if now is None else now
        self._prune(key, now).append(now)

    def hit(self, key: str, now: float | None = None) -> bool:
        """Record an event; return False if it exceeds the limit."""
        now = time.monotonic() if now is None else now
        q = self._prune(key, now)
        if len(q) >= self.max_events:
            return False
        q.append(now)
        return True

    def reset(self, key: str) -> None:
        self._events.pop(key, None)
