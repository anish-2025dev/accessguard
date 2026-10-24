"""Redaction of everything the broker returns (RV-4; PLAN.md §6.14).

The planner (possibly an LLM) and the audit log only ever see: the status code, the *shape* of a
JSON response (keys and value types, never values), whether this run's fixture marker appears in
the body, and the id of a created fixture. Headers are dropped entirely; tokens, JWTs, e-mail
addresses and any value of a vaulted credential are masked wherever text must be kept.
"""

from __future__ import annotations

import json
import re
from typing import Any

JWT = re.compile(r"eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]*")
EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
TOKENISH = re.compile(r"\b[A-Za-z0-9_\-]{32,}\b")
MASK = "[redacted]"


def mask_text(text: str, secrets: list[str] = ()) -> str:  # type: ignore[assignment]
    for s in secrets:
        if s:
            text = text.replace(s, MASK)
    text = JWT.sub(MASK, text)
    text = EMAIL.sub(MASK, text)
    return TOKENISH.sub(MASK, text)


def shape(value: Any, depth: int = 0) -> Any:
    """JSON structure without values: {"id": "int", "items": [{"title": "str"}]}."""
    if depth > 5:
        return "..."
    if isinstance(value, dict):
        return {str(k)[:64]: shape(v, depth + 1) for k, v in list(value.items())[:40]}
    if isinstance(value, list):
        return [shape(value[0], depth + 1)] if value else []
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, int | float):
        return "number"
    if value is None:
        return "null"
    return "str"


def body_shape(body: bytes) -> Any:
    try:
        return shape(json.loads(body))
    except (ValueError, UnicodeDecodeError):
        return "non-json" if body else "empty"


def find_id(body: bytes) -> str | None:
    """The id of a created object: ``{"id": ...}`` or ``{"data": {"id": ...}}``."""
    try:
        data = json.loads(body)
    except (ValueError, UnicodeDecodeError):
        return None
    for obj in (data, data.get("data") if isinstance(data, dict) else None):
        if isinstance(obj, dict):
            for k in ("id", "uuid", "_id", "pk", "slug"):
                v = obj.get(k)
                if isinstance(v, str | int) and not isinstance(v, bool) and str(v):
                    return str(v)
    return None
