"""Per-plugin settings: validated config values, encrypted secrets, and policy.

Stored in <config_dir>/plugins.json. Secret values are encrypted with AES-256-GCM
(context = plugin name + field) and never written in clear.
"""

from __future__ import annotations

import json
import os
import threading
import types
import typing
from pathlib import Path
from typing import Any

from pydantic import BaseModel, SecretStr, ValidationError

from .crypto import SecretBox, SecretError


class Policy(BaseModel):
    """Server-side enforcement; Claude's own per-tool approval is only a convenience."""

    read_only: bool = True
    allow_tools: list[str] = []  # if non-empty, only these tools are served
    deny_tools: list[str] = []  # always wins
    enable_tools: list[str] = []  # write/admin tools are enabled by name, and only when read_only is false
    rate_limit_per_minute: int = 60  # 0 disables
    max_output_bytes: int = 65536

    def allows(self, name: str, tier: str) -> bool:
        if name in self.deny_tools:
            return False
        if self.allow_tools and name not in self.allow_tools:
            return False
        if tier == "read":
            return True
        return (not self.read_only) and name in self.enable_tools


class PluginSettings(BaseModel):
    enabled: bool = True
    values: dict[str, Any] = {}  # non-secret config
    secrets: dict[str, str] = {}  # field -> ciphertext
    policy: Policy = Policy()


class ConfigError(Exception):
    """Message is safe to show: field names and problem kinds, never input values."""


def is_secret_annotation(ann: Any) -> bool:
    if ann is SecretStr:
        return True
    origin = typing.get_origin(ann)
    if origin in (typing.Union, types.UnionType):
        return any(is_secret_annotation(a) for a in typing.get_args(ann))
    if origin is typing.Annotated:
        return is_secret_annotation(typing.get_args(ann)[0])
    return False


def secret_fields(model: type[BaseModel] | None) -> set[str]:
    if model is None:
        return set()
    return {n for n, f in model.model_fields.items() if is_secret_annotation(f.annotation)}


def validate_config(model: type[BaseModel] | None, values: dict[str, Any], secrets: dict[str, str]) -> BaseModel | None:
    if model is None:
        return None
    try:
        return model.model_validate({**values, **secrets})
    except ValidationError as e:
        # e.errors() would echo the offending input (possibly a secret); report loc and message only.
        problems = "; ".join(f"{'.'.join(str(p) for p in err['loc']) or 'config'}: {err['msg']}" for err in e.errors())
        raise ConfigError(f"invalid config ({problems})") from None


class ConfigStore:
    def __init__(self, config_dir: Path, box: SecretBox) -> None:
        self.path = config_dir / "plugins.json"
        self.box = box
        self._lock = threading.Lock()
        config_dir.mkdir(parents=True, exist_ok=True)

    def _read(self) -> dict[str, Any]:
        try:
            return json.loads(self.path.read_text())
        except FileNotFoundError:
            return {}
        except ValueError as e:
            raise ConfigError("plugins.json is not valid JSON") from e

    def _write(self, data: dict[str, Any]) -> None:
        tmp = self.path.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, indent=2, sort_keys=True)
        os.replace(tmp, self.path)

    def get(self, name: str) -> PluginSettings:
        with self._lock:
            return PluginSettings.model_validate(self._read().get(name, {}))

    def decrypted_secrets(self, name: str, settings: PluginSettings | None = None) -> dict[str, str]:
        s = settings or self.get(name)
        out = {}
        for field, token in s.secrets.items():
            try:
                out[field] = self.box.decrypt(token, f"plugin:{name}:{field}")
            except SecretError:
                raise ConfigError(f"cannot decrypt secret '{field}' (wrong MCPOPUS_SECRET_KEY?)") from None
        return out

    def save(self, name: str, *, enabled: bool | None = None, values: dict[str, Any] | None = None,
             new_secrets: dict[str, str] | None = None, clear_secrets: list[str] | None = None,
             policy: Policy | None = None) -> None:
        """Update only what is passed. new_secrets holds clear text, encrypted here."""
        with self._lock:
            data = self._read()
            cur = PluginSettings.model_validate(data.get(name, {}))
            if enabled is not None:
                cur.enabled = enabled
            if values is not None:
                cur.values = values
            for field, plain in (new_secrets or {}).items():
                cur.secrets[field] = self.box.encrypt(plain, f"plugin:{name}:{field}")
            for field in clear_secrets or []:
                cur.secrets.pop(field, None)
            if policy is not None:
                cur.policy = policy
            data[name] = cur.model_dump()
            self._write(data)

    def forget(self, name: str) -> None:
        with self._lock:
            data = self._read()
            if data.pop(name, None) is not None:
                self._write(data)
