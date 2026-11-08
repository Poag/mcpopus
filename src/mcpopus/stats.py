"""Usage statistics, kept in the host's SQLite database.

Recorded per UTC day, plugin, client and tool: calls, errors, refused calls, time, bytes in (the size of the arguments,
never their content) and bytes out (the size of the result). Plugins can add their own named counters through
`ctx.stats.count("bytes_written", n)`. Nothing here records argument values or result content. Recording never raises:
a statistics failure must not break a tool call.
"""

from __future__ import annotations

import logging
import re
import threading
import time
from typing import Any

from .store import Store

log = logging.getLogger("mcpopus.stats")
COUNTER_NAME = re.compile(r"^[a-z][a-z0-9_]{0,39}$")
MAX_COUNTERS_PER_PLUGIN = 20
RETENTION_DAYS = 90


def _day(ts: float | None = None) -> str:
    return time.strftime("%Y-%m-%d", time.gmtime(ts if ts is not None else time.time()))


class StatsHook:
    """What a plugin gets as `ctx.stats`."""

    def __init__(self, stats: Stats, plugin: str) -> None:
        self._stats, self._plugin = stats, plugin

    def count(self, name: str, amount: float = 1) -> None:
        self._stats.count(self._plugin, name, amount)


class Stats:
    def __init__(self, store: Store) -> None:
        self.store = store
        self._lock = threading.Lock()
        self._pending: dict[tuple, tuple[int, float]] = {}

    def hook(self, plugin: str) -> StatsHook:
        return StatsHook(self, plugin)

    # ------------------------------------------------------------- writing
    def record_call(self, plugin: str, client_id: str, tool: str, status: str, ms: float, bytes_in: int, bytes_out: int) -> None:
        now = time.time()
        try:
            self.store._run(
                "INSERT INTO usage(day,plugin,client_id,tool,calls,errors,denied,limited,ms_total,ms_max,bytes_in,bytes_out,last_ts) "
                "VALUES(?,?,?,?,1,?,?,?,?,?,?,?,?) ON CONFLICT(day,plugin,client_id,tool) DO UPDATE SET "
                "calls=calls+1, errors=errors+excluded.errors, denied=denied+excluded.denied, limited=limited+excluded.limited, "
                "ms_total=ms_total+excluded.ms_total, ms_max=MAX(ms_max,excluded.ms_max), bytes_in=bytes_in+excluded.bytes_in, "
                "bytes_out=bytes_out+excluded.bytes_out, last_ts=excluded.last_ts",
                (_day(now), plugin, client_id, tool, int(status == "error"), int(status == "denied"), int(status == "rate_limited"),
                 ms, ms, max(0, bytes_in), max(0, bytes_out), now))
        except Exception:  # noqa: BLE001
            log.warning("could not record usage")

    def count(self, plugin: str, name: str, amount: float = 1) -> None:
        try:
            if not COUNTER_NAME.fullmatch(name) or not isinstance(amount, (int, float)) or amount != amount or amount < 0:
                return
            day = _day()
            known = {r["name"] for r in self.store._all("SELECT DISTINCT name FROM counters WHERE plugin=?", (plugin,))}
            if name not in known and len(known) >= MAX_COUNTERS_PER_PLUGIN:
                return
            self.store._run(
                "INSERT INTO counters(day,plugin,name,value) VALUES(?,?,?,?) ON CONFLICT(day,plugin,name) DO UPDATE SET value=value+excluded.value",
                (day, plugin, name, float(amount)))
        except Exception:  # noqa: BLE001
            log.warning("could not record counter")

    def seen(self, client_id: str, plugin: str, agent: str, protocol: str, ip: str, country: str) -> None:
        """One authenticated request from an agent. Counted in memory and written when new or at most once a minute per agent."""
        try:
            key = (client_id, plugin, agent, protocol, ip, country)
            now = time.time()
            with self._lock:
                pending, last = self._pending.get(key, (0, 0.0))
                pending += 1
                if last and now - last < 60:
                    self._pending[key] = (pending, last)
                    return
                if len(self._pending) >= 2000:  # a flood of distinct agents must not grow memory without limit
                    self._pending.clear()  # held counts are dropped; every agent is then written again on its next request
                self._pending[key] = (0, now)
            self.store._run(
                "INSERT INTO agents(client_id,plugin,agent,protocol,ip,country,requests,first_ts,last_ts) VALUES(?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(client_id,plugin,agent,protocol,ip) DO UPDATE SET requests=requests+excluded.requests, last_ts=excluded.last_ts, country=excluded.country",
                (client_id, plugin, agent, protocol, ip, country, pending, now, now))
        except Exception:  # noqa: BLE001
            log.warning("could not record agent")

    def agents(self, days: int = 30, limit: int = 100) -> list[dict[str, Any]]:
        rows = self.store._all("SELECT * FROM agents WHERE last_ts>=? ORDER BY last_ts DESC LIMIT ?", (time.time() - days * 86400, limit))
        return [dict(r) | {"label": agent_label(r["agent"])} for r in rows]

    def prune(self) -> None:
        cutoff = _day(time.time() - RETENTION_DAYS * 86400)
        self.store._run("DELETE FROM usage WHERE day<?", (cutoff,))
        self.store._run("DELETE FROM counters WHERE day<?", (cutoff,))
        self.store._run("DELETE FROM agents WHERE last_ts<?", (time.time() - RETENTION_DAYS * 86400,))

    # ------------------------------------------------------------- reading
    @staticmethod
    def _since(days: int) -> str:
        return _day(time.time() - (days - 1) * 86400)

    def totals(self, days: int = 1, plugin: str | None = None, client_id: str | None = None) -> dict[str, Any]:
        sql = ("SELECT COALESCE(SUM(calls),0) calls, COALESCE(SUM(errors),0) errors, COALESCE(SUM(denied),0) denied, "
               "COALESCE(SUM(limited),0) limited, COALESCE(SUM(ms_total),0) ms, COALESCE(SUM(bytes_in),0) bytes_in, "
               "COALESCE(SUM(bytes_out),0) bytes_out, COALESCE(MAX(last_ts),0) last FROM usage WHERE day>=?")
        args: list[Any] = [self._since(days)]
        if plugin:
            sql += " AND plugin=?"; args.append(plugin)
        if client_id:
            sql += " AND client_id=?"; args.append(client_id)
        r = self.store._one(sql, tuple(args))
        d = dict(r)
        d["avg_ms"] = round(d["ms"] / d["calls"], 1) if d["calls"] else 0.0
        return d

    def by_plugin(self, days: int = 1) -> dict[str, dict[str, Any]]:
        rows = self.store._all(
            "SELECT plugin, SUM(calls) calls, SUM(errors) errors, SUM(bytes_out) bytes_out, MAX(last_ts) last FROM usage WHERE day>=? GROUP BY plugin",
            (self._since(days),))
        return {r["plugin"]: dict(r) for r in rows}

    def by_tool(self, plugin: str, days: int = 7) -> list[dict[str, Any]]:
        rows = self.store._all(
            "SELECT tool, SUM(calls) calls, SUM(errors) errors, SUM(denied) denied, SUM(limited) limited, SUM(ms_total) ms, MAX(ms_max) ms_max, "
            "SUM(bytes_in) bytes_in, SUM(bytes_out) bytes_out, MAX(last_ts) last FROM usage WHERE plugin=? AND day>=? GROUP BY tool ORDER BY calls DESC",
            (plugin, self._since(days)))
        out = []
        for r in rows:
            d = dict(r)
            d["avg_ms"] = round(d["ms"] / d["calls"], 1) if d["calls"] else 0.0
            out.append(d)
        return out

    def by_client(self, days: int = 30) -> dict[str, dict[str, Any]]:
        rows = self.store._all(
            "SELECT client_id, SUM(calls) calls, SUM(errors) errors, SUM(bytes_out) bytes_out, MAX(last_ts) last FROM usage WHERE day>=? GROUP BY client_id",
            (self._since(days),))
        return {r["client_id"]: dict(r) for r in rows}

    def per_day(self, plugin: str | None = None, days: int = 14) -> list[dict[str, Any]]:
        """One entry per day, oldest first, with empty days filled in (for a small bar chart)."""
        sql, args = "SELECT day, SUM(calls) calls, SUM(errors) errors FROM usage WHERE day>=?", [self._since(days)]
        if plugin:
            sql += " AND plugin=?"; args.append(plugin)
        have = {r["day"]: r for r in self.store._all(sql + " GROUP BY day", tuple(args))}
        out = []
        for i in range(days - 1, -1, -1):
            d = _day(time.time() - i * 86400)
            r = have.get(d)
            out.append({"day": d, "calls": int(r["calls"]) if r else 0, "errors": int(r["errors"]) if r else 0})
        return out

    def counters(self, plugin: str, days: int = 30) -> dict[str, float]:
        rows = self.store._all("SELECT name, SUM(value) v FROM counters WHERE plugin=? AND day>=? GROUP BY name ORDER BY name", (plugin, self._since(days)))
        return {r["name"]: r["v"] for r in rows}


_CTRL = re.compile(r"[\x00-\x1f\x7f]")


def clean_header(value: str, limit: int = 160) -> str:
    """A header value from the network, made safe to store and show: no control characters, bounded length."""
    return _CTRL.sub(" ", value).strip()[:limit]


def agent_label(user_agent: str) -> str:
    """A short name for a User-Agent string. Display only: the header is supplied by the caller and proves nothing."""
    ua = user_agent.lower()
    if not ua:
        return "unknown"
    for needle, label in (("claude", "Claude"), ("anthropic", "Anthropic"), ("chatgpt", "ChatGPT"), ("openai", "OpenAI"), ("cursor", "Cursor"),
                          ("vscode", "VS Code"), ("python-httpx", "Python httpx"), ("httpx", "Python httpx"), ("python-requests", "Python requests"),
                          ("node", "Node.js"), ("undici", "Node.js"), ("curl", "curl"), ("mozilla", "Browser")):
        if needle in ua:
            return label
    return user_agent.split("/")[0].split(" ")[0][:30] or "unknown"


def human_bytes(n: float) -> str:
    n = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} GB"


def ago(ts: float) -> str:
    if not ts:
        return "never"
    s = int(time.time() - ts)
    return "just now" if s < 60 else f"{s // 60}m ago" if s < 3600 else f"{s // 3600}h ago" if s < 86400 else f"{s // 86400}d ago"
