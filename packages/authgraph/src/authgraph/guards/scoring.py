"""Guard seeds and feature scoring (FR-7.6, rules only; LLM classification arrives in Phase 3).

A dependency is a *guard* when it can stop a request: it raises 401/403 (directly or through a
helper) or is a known security primitive. Kinds follow PLAN.md §6.2. Confidence below
``CONFIRMED`` never makes an endpoint AUTH, so weak evidence yields UNKNOWN/NO_AUTH, not silence.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from authgraph.facts.models import GuardKind, OnFail
from authgraph.lang.python.summary import Function, RaiseInfo, Value

CONFIRMED = 0.7

# fastapi.security classes, verified against fastapi 0.161.0 (`fastapi/security/__init__.py`):
# each accepts `auto_error` (default True -> 401/403 when credentials are missing).
FASTAPI_SECURITY = frozenset(
    {
        "APIKeyCookie",
        "APIKeyHeader",
        "APIKeyQuery",
        "HTTPBasic",
        "HTTPBearer",
        "HTTPDigest",
        "OAuth2",
        "OAuth2AuthorizationCodeBearer",
        "OAuth2PasswordBearer",
        "OpenIdConnect",
    }
)
# Request-parsing helpers from fastapi.security that never reject a request on their own.
NON_GUARD_EXTERNAL = frozenset(
    {
        "OAuth2PasswordRequestForm",
        "OAuth2PasswordRequestFormStrict",
        "HTTPAuthorizationCredentials",
        "HTTPBasicCredentials",
        "SecurityScopes",
    }
)
AUTH_NAME = re.compile(
    r"(auth|current_?\w*user|login|require|verify|permission|admin|role|token|guard|protect|"
    r"owner|member|staff|superuser|access|principal|session|scope|jwt|api_?key|privilege)",
    re.I,
)
AUTHISH_EXTERNAL = re.compile(
    r"(auth|current_?\w*user|token|login|permission|role|admin|verif|jwt|security|principal|"
    r"guard|require|access|credential|api_?key|scope|superuser|logged_?in)",
    re.I,
)


@dataclass
class GuardInfo:
    kind: GuardKind
    confidence: float
    on_fail: OnFail
    condition: str | None = None  # JSON formula: the guard rejects when this holds


def builtin_external(qualified: str, call: Value | None) -> GuardInfo | None:
    """Known security primitives from libraries (seeds). ``call`` is the constructor/factory."""
    last = qualified.split(".")[-1]
    kwargs = call.kwargs if call else {}

    def flag(name: str) -> bool:
        v = kwargs.get(name)
        return bool(v and v.kind == "const" and v.const is True)

    if last in FASTAPI_SECURITY and (
        qualified.startswith("fastapi.")
        or qualified.startswith("starlette.")
        or "." not in qualified
    ):
        auto = kwargs.get("auto_error")
        if auto is not None and auto.kind == "const" and auto.const is False:
            return GuardInfo(GuardKind.OPTIONAL_AUTHN, 1.0, "none")
        return GuardInfo(GuardKind.AUTHN, 0.8, "raise")
    # fastapi-users: FastAPIUsers.current_user(optional, active, verified, superuser)
    # (fastapi_users/authentication/authenticator.py at the pinned corpus ref).
    if last in {"current_user", "current_user_token"}:
        if flag("optional"):
            return GuardInfo(GuardKind.OPTIONAL_AUTHN, 1.0, "none")
        if flag("superuser"):
            return GuardInfo(GuardKind.AUTHZ_ROLE, 1.0, "raise")
        return GuardInfo(GuardKind.AUTHN, 1.0, "raise")
    return None


def _or(conds: list[str | None]) -> str | None:
    parsed: list[Any] = []
    for c in conds:
        if c is None:
            return json.dumps(["atom", "True"])  # unconditional rejection on some path
        parsed.append(json.loads(c))
    if not parsed:
        return None
    return json.dumps(parsed[0] if len(parsed) == 1 else ["or", *parsed])


_OWNER_ATOM = re.compile(
    r"\b(owner_id|user_id|owner|author_id|created_by\w*|account_id|tenant_id|org_id)\b"
)
_ROLE_ATOM = re.compile(
    r"\b(role|roles|user_role|is_superuser|is_admin|is_staff|scopes|permissions|groups|admin|"
    r"superuser)\b"
)


def auth_raises(fn: Function) -> list[RaiseInfo]:
    """Raises that reject a caller: 401/403, or 400/404 guarded by an ownership/role predicate
    (apps often answer "not yours" with 400 or 404 to avoid leaking existence)."""
    out = []
    for r in fn.raises:
        if r.status in (401, 403) or (
            r.status in (400, 404)
            and r.condition
            and (_OWNER_ATOM.search(r.condition) or _ROLE_ATOM.search(r.condition))
        ):
            out.append(r)
    return out


def classify(
    fn: Function, helpers: list[Function], uses_scheme: bool, after_authn: bool = False
) -> GuardInfo | None:
    """Score one dependency function. ``helpers`` are local functions it calls (depth 1)."""
    raises = auth_raises(fn)
    helper_raise = any(r.status in (401, 403) for h in helpers for r in h.raises)
    token = fn.token_decode or any(h.token_decode for h in helpers)
    auth_feature = token or fn.reads_authorization or uses_scheme
    named = bool(AUTH_NAME.search(fn.name))

    if (raises or helper_raise or token) and re.search(r"optional|maybe", fn.name, re.I):
        return GuardInfo(GuardKind.OPTIONAL_AUTHN, 0.8, "none")
    if raises or helper_raise:
        statuses = {r.status for r in raises}
        conds = " ".join(r.condition or "" for r in raises)
        cond = _or([r.condition for r in raises]) if raises else None
        if fn.owner_compare and (_OWNER_ATOM.search(conds) or not _ROLE_ATOM.search(conds)):
            # Kind comes from the predicate, not the status code, so 400 -> 403 is no change.
            return GuardInfo(GuardKind.AUTHZ_OWNER, 0.85, "raise", cond)
        if _ROLE_ATOM.search(conds) or (403 in statuses and fn.role_refs):
            return GuardInfo(GuardKind.AUTHZ_ROLE, 0.9, "raise", cond)
        if statuses == {403} and after_authn:
            # Only "forbidden", and it runs after authentication: a permission check.
            return GuardInfo(GuardKind.AUTHZ_ROLE, 0.85, "raise", cond)
        if 401 in statuses or auth_feature or helper_raise:
            conf = 0.9 if (auth_feature or named or helper_raise) else 0.75
            return GuardInfo(GuardKind.AUTHN, conf, "raise", cond)
        if 403 in statuses:
            return GuardInfo(GuardKind.AUTHZ_ROLE, 0.8 if named else 0.7, "raise", cond)
    if token or (auth_feature and named):
        swallowed = [e for e in fn.excepts if e.body in ("log_only", "pass")]
        if swallowed:
            # Looks like authentication but every failure path is swallowed (FR-3.5 neutered).
            return GuardInfo(GuardKind.FAKE, 0.8, "log_only")
        if fn.returns_none:
            return GuardInfo(GuardKind.OPTIONAL_AUTHN, 0.8, "none")
        if not any(r.status for r in fn.raises) and token:
            return GuardInfo(GuardKind.FAKE, 0.7, "none")
    return None
