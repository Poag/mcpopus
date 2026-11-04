"""Owner credentials: Argon2id password hashing and RFC 6238 TOTP."""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

# argon2-cffi defaults follow RFC 9106 section 4 "low memory" profile (Argon2id).
_hasher = PasswordHasher()
_DUMMY_HASH = _hasher.hash(secrets.token_urlsafe(16))

MIN_PASSWORD_LENGTH = 14


def check_password_policy(password: str) -> str | None:
    if len(password) < MIN_PASSWORD_LENGTH:
        return f"password must be at least {MIN_PASSWORD_LENGTH} characters"
    if len(set(password)) < 6:
        return "password is too repetitive"
    return None


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(stored_hash: str | None, password: str) -> bool:
    """Always performs one Argon2 verification, so that a missing credential
    costs the same as a wrong password."""
    try:
        _hasher.verify(stored_hash or _DUMMY_HASH, password)
        return stored_hash is not None
    except (VerificationError, InvalidHashError):
        return False


# --- TOTP (RFC 6238, HMAC-SHA1, 6 digits, 30 s) ---------------------------------

TOTP_PERIOD = 30
TOTP_DIGITS = 6


def new_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def valid_totp_secret(secret_b32: str) -> bool:
    try:
        return len(base64.b32decode(secret_b32 + "=" * (-len(secret_b32) % 8), casefold=True)) >= 10
    except ValueError:
        return False


def _hotp(secret_b32: str, counter: int) -> str:
    key = base64.b32decode(secret_b32 + "=" * (-len(secret_b32) % 8), casefold=True)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = (struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF) % 10**TOTP_DIGITS
    return str(code).zfill(TOTP_DIGITS)


def totp_at(secret_b32: str, at: float) -> str:
    return _hotp(secret_b32, int(at // TOTP_PERIOD))


def verify_totp(secret_b32: str, code: str, last_step: int, now: float | None = None) -> int | None:
    """Return the matched time step, or None. Steps at or before last_step are
    rejected, so a code cannot be replayed. Accepts one step either side."""
    code = code.strip().replace(" ", "")
    if len(code) != TOTP_DIGITS or not code.isdigit():
        return None
    step_now = int((time.time() if now is None else now) // TOTP_PERIOD)
    matched = None
    for step in (step_now - 1, step_now, step_now + 1):  # evaluate all: no early exit
        if hmac.compare_digest(_hotp(secret_b32, step), code) and step > last_step:
            matched = step
    return matched


def provisioning_uri(secret_b32: str, account: str, issuer: str = "mcpopus") -> str:
    return (
        f"otpauth://totp/{quote(issuer)}:{quote(account)}"
        f"?secret={secret_b32}&issuer={quote(issuer)}&digits={TOTP_DIGITS}&period={TOTP_PERIOD}"
    )
