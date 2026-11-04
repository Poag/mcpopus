"""Render a plugin's pydantic Config as an HTML form, and read the submission back."""

from __future__ import annotations

import enum
import json
import types
import typing
from dataclasses import dataclass, field
from typing import Any, Literal

from pydantic import BaseModel
from pydantic_core import PydanticUndefined

from .pluginconfig import is_secret_annotation


@dataclass
class FieldSpec:
    name: str
    label: str
    kind: str  # text number checkbox select lines json secret
    description: str = ""
    required: bool = False
    default: Any = None
    options: list[str] = field(default_factory=list)
    step: str | None = None
    value: Any = None  # current non-secret value
    secret_set: bool = False


def _unwrap(ann: Any) -> Any:
    origin = typing.get_origin(ann)
    if origin is typing.Annotated:
        return _unwrap(typing.get_args(ann)[0])
    if origin in (typing.Union, types.UnionType):
        args = [a for a in typing.get_args(ann) if a is not type(None)]
        return _unwrap(args[0]) if len(args) == 1 else ann
    return ann


def classify(ann: Any) -> tuple[str, list[str]]:
    if is_secret_annotation(ann):
        return "secret", []
    a = _unwrap(ann)
    origin = typing.get_origin(a)
    if a is bool:
        return "checkbox", []
    if a is int:
        return "number", []
    if a is float:
        return "float", []
    if origin is Literal:
        return "select", [str(x) for x in typing.get_args(a)]
    if isinstance(a, type) and issubclass(a, enum.Enum):
        return "select", [str(m.value) for m in a]
    if origin in (list, set, tuple) and typing.get_args(a) and _unwrap(typing.get_args(a)[0]) is str:
        return "lines", []
    if a is str:
        return "text", []
    return "json", []


def describe(model: type[BaseModel], values: dict[str, Any], secrets_set: set[str]) -> list[FieldSpec]:
    specs = []
    for name, f in model.model_fields.items():
        kind, options = classify(f.annotation)
        default = None if f.default is PydanticUndefined else f.default
        value = values.get(name, default)
        if kind == "lines" and isinstance(value, (list, tuple, set)):
            value = "\n".join(str(v) for v in value)
        elif kind == "json" and value is not None:
            value = json.dumps(value)
        specs.append(FieldSpec(
            name=name, label=f.title or name.replace("_", " ").capitalize(), kind="number" if kind == "float" else kind,
            description=f.description or "", required=f.is_required(), default=default, options=options,
            step="any" if kind == "float" else None, value=None if kind == "secret" else value,
            secret_set=name in secrets_set,
        ))
    return specs


def parse(model: type[BaseModel], form: dict[str, str]) -> tuple[dict[str, Any], dict[str, str], list[str]]:
    """Return (values, new_secrets, secrets_to_clear). A blank secret field keeps the stored value."""
    values: dict[str, Any] = {}
    new_secrets: dict[str, str] = {}
    clear: list[str] = []
    for name, f in model.model_fields.items():
        kind, _ = classify(f.annotation)
        raw = form.get(f"f_{name}")
        if kind == "secret":
            if form.get(f"clear_{name}") == "1":
                clear.append(name)
            elif raw:
                new_secrets[name] = raw
        elif kind == "checkbox":
            values[name] = form.get(f"f_{name}") == "1"
        elif raw is None or (raw.strip() == "" and kind != "text"):
            continue  # leave unset: the model default (or a required-field error) applies
        elif kind == "lines":
            values[name] = [ln.strip() for ln in raw.splitlines() if ln.strip()]
        elif kind == "json":
            try:
                values[name] = json.loads(raw)
            except ValueError:
                values[name] = raw  # validation will reject it with a readable message
        else:
            values[name] = raw.strip()  # pasted values often carry a stray space or newline (secrets are left as typed)
    return values, new_secrets, clear
