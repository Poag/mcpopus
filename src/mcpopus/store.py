"""SQLite persistence: credentials, OAuth clients, grants, codes, tokens, admin sessions.

Tokens, codes and session ids are stored as SHA-256 hashes only.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS credentials (
  realm TEXT PRIMARY KEY, password_hash TEXT NOT NULL, totp_secret_enc TEXT NOT NULL,
  totp_last_step INTEGER NOT NULL DEFAULT 0, updated_at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS clients (
  client_id TEXT PRIMARY KEY, secret_hash TEXT, name TEXT NOT NULL, redirect_uris TEXT NOT NULL,
  kind TEXT NOT NULL, resource TEXT, created_at REAL NOT NULL, revoked INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS auth_requests (
  id TEXT PRIMARY KEY, client_id TEXT NOT NULL, redirect_uri TEXT NOT NULL, state TEXT,
  code_challenge TEXT NOT NULL, resource TEXT NOT NULL, scope TEXT NOT NULL, csrf TEXT NOT NULL,
  failures INTEGER NOT NULL DEFAULT 0, expires_at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS grants (
  id TEXT PRIMARY KEY, client_id TEXT NOT NULL, resource TEXT NOT NULL, scope TEXT NOT NULL,
  created_at REAL NOT NULL, revoked_at REAL);
CREATE TABLE IF NOT EXISTS codes (
  code_hash TEXT PRIMARY KEY, grant_id TEXT NOT NULL, client_id TEXT NOT NULL, redirect_uri TEXT NOT NULL,
  code_challenge TEXT NOT NULL, expires_at REAL NOT NULL, used INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS tokens (
  token_hash TEXT PRIMARY KEY, kind TEXT NOT NULL, grant_id TEXT NOT NULL,
  created_at REAL NOT NULL, expires_at REAL NOT NULL, used_at REAL);
CREATE INDEX IF NOT EXISTS tokens_grant ON tokens(grant_id);
CREATE TABLE IF NOT EXISTS usage (
  day TEXT NOT NULL, plugin TEXT NOT NULL, client_id TEXT NOT NULL, tool TEXT NOT NULL,
  calls INTEGER NOT NULL DEFAULT 0, errors INTEGER NOT NULL DEFAULT 0, denied INTEGER NOT NULL DEFAULT 0,
  limited INTEGER NOT NULL DEFAULT 0, ms_total REAL NOT NULL DEFAULT 0, ms_max REAL NOT NULL DEFAULT 0,
  bytes_in INTEGER NOT NULL DEFAULT 0, bytes_out INTEGER NOT NULL DEFAULT 0, last_ts REAL NOT NULL DEFAULT 0,
  PRIMARY KEY (day, plugin, client_id, tool));
CREATE TABLE IF NOT EXISTS agents (
  client_id TEXT NOT NULL, plugin TEXT NOT NULL, agent TEXT NOT NULL, protocol TEXT NOT NULL, ip TEXT NOT NULL, country TEXT NOT NULL,
  requests INTEGER NOT NULL DEFAULT 0, first_ts REAL NOT NULL, last_ts REAL NOT NULL,
  PRIMARY KEY (client_id, plugin, agent, protocol, ip));
CREATE TABLE IF NOT EXISTS counters (
  day TEXT NOT NULL, plugin TEXT NOT NULL, name TEXT NOT NULL, value REAL NOT NULL DEFAULT 0,
  PRIMARY KEY (day, plugin, name));
CREATE TABLE IF NOT EXISTS admin_sessions (
  id_hash TEXT PRIMARY KEY, csrf TEXT NOT NULL, created_at REAL NOT NULL, expires_at REAL NOT NULL);
"""


@dataclass(frozen=True)
class Client:
    client_id: str
    secret_hash: str | None
    name: str
    redirect_uris: tuple[str, ...]
    kind: str
    resource: str | None
    created_at: float
    revoked: bool


@dataclass(frozen=True)
class Principal:
    """The authenticated caller of a plugin endpoint."""

    client_id: str
    grant_id: str
    resource: str


class Store:
    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._db.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        with self._lock:
            self._db.execute("PRAGMA journal_mode=WAL")
            self._db.execute("PRAGMA foreign_keys=ON")
            self._db.executescript(SCHEMA)
            cols = {r["name"] for r in self._db.execute("PRAGMA table_info(admin_sessions)")}
            for col, ddl in (("enrol_only", "INTEGER NOT NULL DEFAULT 0"), ("pending_realm", "TEXT"), ("pending_totp_enc", "TEXT")):
                if col not in cols:
                    self._db.execute(f"ALTER TABLE admin_sessions ADD COLUMN {col} {ddl}")
        try:
            path.chmod(0o600)
        except OSError:
            pass

    def close(self) -> None:
        with self._lock:
            self._db.close()

    def _run(self, sql: str, args: tuple[Any, ...] = ()) -> sqlite3.Cursor:
        with self._lock:
            return self._db.execute(sql, args)

    def _one(self, sql: str, args: tuple[Any, ...] = ()) -> sqlite3.Row | None:
        with self._lock:
            return self._db.execute(sql, args).fetchone()

    def _all(self, sql: str, args: tuple[Any, ...] = ()) -> list[sqlite3.Row]:
        with self._lock:
            return self._db.execute(sql, args).fetchall()

    # --- credentials -------------------------------------------------------
    def get_credential(self, realm: str) -> sqlite3.Row | None:
        return self._one("SELECT * FROM credentials WHERE realm=?", (realm,))

    def set_credential(self, realm: str, password_hash: str, totp_secret_enc: str) -> None:
        self._run(
            "INSERT INTO credentials(realm,password_hash,totp_secret_enc,totp_last_step,updated_at)"
            " VALUES(?,?,?,0,?) ON CONFLICT(realm) DO UPDATE SET password_hash=excluded.password_hash,"
            " totp_secret_enc=excluded.totp_secret_enc, totp_last_step=0, updated_at=excluded.updated_at",
            (realm, password_hash, totp_secret_enc, time.time()),
        )

    def set_password(self, realm: str, password_hash: str) -> None:
        self._run("UPDATE credentials SET password_hash=?, updated_at=? WHERE realm=?", (password_hash, time.time(), realm))

    def set_totp(self, realm: str, totp_secret_enc: str, step: int = 0) -> bool:
        cur = self._run("UPDATE credentials SET totp_secret_enc=?, totp_last_step=?, updated_at=? WHERE realm=?", (totp_secret_enc, step, time.time(), realm))
        return cur.rowcount == 1

    def advance_totp_step(self, realm: str, step: int) -> bool:
        """Atomically record a used TOTP step; False if it was already used."""
        cur = self._run(
            "UPDATE credentials SET totp_last_step=? WHERE realm=? AND totp_last_step<?", (step, realm, step)
        )
        return cur.rowcount == 1

    # --- clients -----------------------------------------------------------
    @staticmethod
    def _client(row: sqlite3.Row) -> Client:
        return Client(
            row["client_id"], row["secret_hash"], row["name"], tuple(json.loads(row["redirect_uris"])),
            row["kind"], row["resource"], row["created_at"], bool(row["revoked"]),
        )

    def add_client(self, c: Client) -> None:
        self._run(
            "INSERT INTO clients(client_id,secret_hash,name,redirect_uris,kind,resource,created_at,revoked)"
            " VALUES(?,?,?,?,?,?,?,0)",
            (c.client_id, c.secret_hash, c.name, json.dumps(list(c.redirect_uris)), c.kind, c.resource, c.created_at),
        )

    def get_client(self, client_id: str) -> Client | None:
        row = self._one("SELECT * FROM clients WHERE client_id=?", (client_id,))
        return self._client(row) if row else None

    def list_clients(self) -> list[Client]:
        return [self._client(r) for r in self._all("SELECT * FROM clients ORDER BY created_at")]

    def revoke_client(self, client_id: str) -> bool:
        cur = self._run("UPDATE clients SET revoked=1 WHERE client_id=?", (client_id,))
        self._run(
            "UPDATE grants SET revoked_at=? WHERE client_id=? AND revoked_at IS NULL", (time.time(), client_id)
        )
        return cur.rowcount == 1

    def delete_client(self, client_id: str) -> None:
        self._run("DELETE FROM clients WHERE client_id=?", (client_id,))

    def count_dcr_clients(self) -> int:
        return self._one("SELECT COUNT(*) AS n FROM clients WHERE kind='dcr'")["n"]

    def prune_unused_dcr_clients(self, older_than: float) -> int:
        cur = self._run(
            "DELETE FROM clients WHERE kind='dcr' AND created_at<? AND client_id NOT IN (SELECT client_id FROM grants)",
            (older_than,),
        )
        return cur.rowcount

    # --- authorisation requests -------------------------------------------
    def add_auth_request(self, **f: Any) -> None:
        self._run(
            "INSERT INTO auth_requests(id,client_id,redirect_uri,state,code_challenge,resource,scope,csrf,expires_at)"
            " VALUES(:id,:client_id,:redirect_uri,:state,:code_challenge,:resource,:scope,:csrf,:expires_at)", f
        )

    def get_auth_request(self, req_id: str) -> sqlite3.Row | None:
        row = self._one("SELECT * FROM auth_requests WHERE id=?", (req_id,))
        if row and row["expires_at"] < time.time():
            self.delete_auth_request(req_id)
            return None
        return row

    def delete_auth_request(self, req_id: str) -> None:
        self._run("DELETE FROM auth_requests WHERE id=?", (req_id,))

    def bump_auth_failure(self, req_id: str) -> int:
        self._run("UPDATE auth_requests SET failures=failures+1 WHERE id=?", (req_id,))
        row = self._one("SELECT failures FROM auth_requests WHERE id=?", (req_id,))
        return row["failures"] if row else 99

    def purge_expired(self) -> None:
        now = time.time()
        self._run("DELETE FROM auth_requests WHERE expires_at<?", (now,))
        self._run("DELETE FROM codes WHERE expires_at<?", (now,))
        self._run("DELETE FROM tokens WHERE expires_at<?", (now,))
        self._run("DELETE FROM admin_sessions WHERE expires_at<?", (now,))

    # --- grants, codes, tokens --------------------------------------------
    def add_grant(self, grant_id: str, client_id: str, resource: str, scope: str) -> None:
        self._run(
            "INSERT INTO grants(id,client_id,resource,scope,created_at) VALUES(?,?,?,?,?)",
            (grant_id, client_id, resource, scope, time.time()),
        )

    def get_grant(self, grant_id: str) -> sqlite3.Row | None:
        return self._one("SELECT * FROM grants WHERE id=?", (grant_id,))

    def list_grants(self) -> list[sqlite3.Row]:
        return self._all(
            "SELECT g.*, c.name AS client_name FROM grants g JOIN clients c ON c.client_id=g.client_id"
            " ORDER BY g.created_at DESC"
        )

    def revoke_grant(self, grant_id: str) -> bool:
        cur = self._run(
            "UPDATE grants SET revoked_at=? WHERE id=? AND revoked_at IS NULL", (time.time(), grant_id)
        )
        self._run("DELETE FROM tokens WHERE grant_id=?", (grant_id,))
        return cur.rowcount == 1

    def add_code(self, code_hash: str, grant_id: str, client_id: str, redirect_uri: str, challenge: str, expires_at: float) -> None:
        self._run(
            "INSERT INTO codes(code_hash,grant_id,client_id,redirect_uri,code_challenge,expires_at) VALUES(?,?,?,?,?,?)",
            (code_hash, grant_id, client_id, redirect_uri, challenge, expires_at),
        )

    def consume_code(self, code_hash: str) -> tuple[sqlite3.Row | None, bool]:
        """Return (row, first_use). A second use returns first_use=False."""
        with self._lock:
            row = self._one("SELECT * FROM codes WHERE code_hash=?", (code_hash,))
            if row is None:
                return None, False
            cur = self._run("UPDATE codes SET used=1 WHERE code_hash=? AND used=0", (code_hash,))
            return row, cur.rowcount == 1

    def add_token(self, token_hash: str, kind: str, grant_id: str, expires_at: float) -> None:
        self._run(
            "INSERT INTO tokens(token_hash,kind,grant_id,created_at,expires_at) VALUES(?,?,?,?,?)",
            (token_hash, kind, grant_id, time.time(), expires_at),
        )

    def get_token(self, token_hash: str) -> sqlite3.Row | None:
        return self._one("SELECT * FROM tokens WHERE token_hash=?", (token_hash,))

    def mark_refresh_used(self, token_hash: str) -> bool:
        cur = self._run(
            "UPDATE tokens SET used_at=? WHERE token_hash=? AND kind='refresh' AND used_at IS NULL",
            (time.time(), token_hash),
        )
        return cur.rowcount == 1

    def delete_token(self, token_hash: str) -> None:
        self._run("DELETE FROM tokens WHERE token_hash=?", (token_hash,))

    def lookup_access(self, token_hash: str) -> sqlite3.Row | None:
        """Active access token joined with its grant and client, or None."""
        return self._one(
            "SELECT t.grant_id, g.client_id, g.resource FROM tokens t"
            " JOIN grants g ON g.id=t.grant_id JOIN clients c ON c.client_id=g.client_id"
            " WHERE t.token_hash=? AND t.kind='access' AND t.expires_at>? AND g.revoked_at IS NULL AND c.revoked=0",
            (token_hash, time.time()),
        )

    # --- admin sessions ----------------------------------------------------
    def add_admin_session(self, id_hash: str, csrf: str, expires_at: float, enrol_only: bool = False) -> None:
        self._run(
            "INSERT INTO admin_sessions(id_hash,csrf,created_at,expires_at,enrol_only) VALUES(?,?,?,?,?)",
            (id_hash, csrf, time.time(), expires_at, int(enrol_only)),
        )

    def set_session_pending(self, id_hash: str, realm: str | None, enc: str | None) -> None:
        self._run("UPDATE admin_sessions SET pending_realm=?, pending_totp_enc=? WHERE id_hash=?", (realm, enc, id_hash))

    def end_enrol_only(self, id_hash: str) -> None:
        self._run("UPDATE admin_sessions SET enrol_only=0, pending_realm=NULL, pending_totp_enc=NULL WHERE id_hash=?", (id_hash,))

    def get_admin_session(self, id_hash: str) -> sqlite3.Row | None:
        return self._one("SELECT * FROM admin_sessions WHERE id_hash=? AND expires_at>?", (id_hash, time.time()))

    def extend_admin_session(self, id_hash: str, expires_at: float) -> None:
        self._run("UPDATE admin_sessions SET expires_at=? WHERE id_hash=?", (expires_at, id_hash))

    def delete_admin_session(self, id_hash: str) -> None:
        self._run("DELETE FROM admin_sessions WHERE id_hash=?", (id_hash,))
