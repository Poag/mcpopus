"""Secret encryption (AES-256-GCM) and token hashing."""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_PREFIX = "v1:"


class SecretError(Exception):
    """Decryption failed: wrong key, wrong context or tampered data."""


def _b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


class SecretBox:
    """Authenticated encryption. The context string is bound as associated data,
    so a ciphertext stored for one field cannot be replayed into another."""

    def __init__(self, key: bytes) -> None:
        if len(key) != 32:
            raise ValueError("secret key must be 32 bytes (base64url encoded)")
        self._aes = AESGCM(key)

    @classmethod
    def from_text(cls, text: str) -> SecretBox:
        try:
            return cls(_b64d(text.strip()))
        except (ValueError, TypeError):
            raise ValueError("secret key must be 32 bytes, base64url encoded") from None

    def encrypt(self, plaintext: str, context: str) -> str:
        nonce = os.urandom(12)
        ct = self._aes.encrypt(nonce, plaintext.encode(), context.encode())
        return _PREFIX + base64.urlsafe_b64encode(nonce + ct).decode()

    def decrypt(self, token: str, context: str) -> str:
        if not token.startswith(_PREFIX):
            raise SecretError("unrecognised secret format")
        try:
            raw = _b64d(token[len(_PREFIX) :])
            return self._aes.decrypt(raw[:12], raw[12:], context.encode()).decode()
        except (InvalidTag, ValueError):
            raise SecretError("cannot decrypt secret") from None


def generate_key() -> str:
    return base64.urlsafe_b64encode(os.urandom(32)).decode()


def new_token(prefix: str, nbytes: int = 32) -> str:
    return f"{prefix}_{secrets.token_urlsafe(nbytes)}"


def hash_token(token: str) -> str:
    """SHA-256 of a high-entropy random token. Tokens carry 256 bits, so a fast
    hash is appropriate (a slow KDF is for human-chosen passwords)."""
    return hashlib.sha256(token.encode()).hexdigest()


def ct_equal(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())
