"""Access fact model (PLAN.md §6.2): the one contract every analyzer writes and every rule reads."""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class Verdict(StrEnum):
    AUTH = "auth"
    NO_AUTH = "no_auth"
    UNKNOWN = "unknown"


class GuardKind(StrEnum):
    AUTHN = "authn"
    OPTIONAL_AUTHN = "optional_authn"
    AUTHZ_ROLE = "authz_role"
    AUTHZ_OWNER = "authz_owner"
    FAKE = "fake"


ENFORCING_KINDS = frozenset({GuardKind.AUTHN, GuardKind.AUTHZ_ROLE, GuardKind.AUTHZ_OWNER})

OnFail = Literal["raise", "return_4xx", "log_only", "none", "unknown"]
GuardSource = Literal["builtin", "config", "scored", "llm"]


class _Model(BaseModel):
    model_config = ConfigDict(frozen=False, extra="forbid")


class Loc(_Model):
    path: str
    line: int
    col: int = 0
    blob_sha: str = ""


class GuardRef(_Model):
    symbol: str  # "app.deps.get_current_user"
    kind: GuardKind
    source: GuardSource
    confidence: float
    inherited_from: Loc | None = None  # include_router / app-level dependency that applied it
    dominates_sink: bool | None = None  # runs before the first sensitive sink
    on_fail: OnFail = "unknown"
    # Guard predicate (raise condition) as a normalized boolean expression, for the Z3 check.
    condition: str | None = None
    loc: Loc | None = None


class Sink(_Model):
    kind: Literal["read", "write", "delete"]
    orm: str  # "sqlalchemy.query", "sqlalchemy.session.get"
    model: str | None
    id_param: str | None  # request param that reaches this sink
    principal_scoped: bool  # predicate includes current user / tenant
    loc: Loc


class Endpoint(_Model):
    id: str  # stable: f"{method} {normalized_path}"
    method: str
    path: str  # may contain <dynamic>
    framework: Literal["fastapi", "express", "nextjs"]
    handler: str
    loc: Loc
    guards: list[GuardRef] = Field(default_factory=list)
    authn: Verdict = Verdict.UNKNOWN
    sensitivity: set[str] = Field(default_factory=set)
    sinks: list[Sink] = Field(default_factory=list)
    public_by_config: bool = False
    # Mounted sub-application whose parent app enforces auth that the mount does not inherit.
    mounted_under_auth: bool = False
    # Include/mount chain from the root app to this route, for evidence.
    chain: list[Loc] = Field(default_factory=list)
    unresolved: list[str] = Field(default_factory=list)  # dependencies we could not resolve
    # Mass assignment of privileged fields from the request body (AG-ROLE-002).
    mass_assign_fields: list[str] = Field(default_factory=list)
    router_group: str = ""  # router identity, used for peer-group comparisons
    # Names in the handler that hold the authenticated principal (FR-3.3 IDOR).
    principals: list[str] = Field(default_factory=list)
    # The handler or a callee compares the principal with a fetched object (owner check).
    owner_check: bool = False
    # Express: auth middleware that covers this path but is registered after the route, so it
    # never runs for it (PLAN.md §6.4 guard chain).
    late_guards: list[GuardRef] = Field(default_factory=list)
    # Express: a route registration made only of middleware (``app.get(p, isAuthorized())``)
    # whose final handler is registered dynamically elsewhere.
    guard_only: bool = False


class DataExposure(_Model):  # Supabase / Firebase
    resource: str
    role: str
    ops: set[str]
    reason: str
    proven: bool = False
    loc: Loc


class SecretExposure(_Model):
    kind: str
    client_side: bool
    loc: Loc
    detail: str = ""


class Coverage(_Model):
    files_total: int = 0
    files_parsed: int = 0
    parse_errors: list[str] = Field(default_factory=list)
    unresolved_imports: int = 0
    endpoints: int = 0
    unknown: int = 0
    cache_hits: int = 0

    @property
    def unknown_rate(self) -> float:
        return self.unknown / self.endpoints if self.endpoints else 0.0


class FactGraph(_Model):
    commit_sha: str
    endpoints: list[Endpoint] = Field(default_factory=list)
    data_exposures: list[DataExposure] = Field(default_factory=list)
    secrets: list[SecretExposure] = Field(default_factory=list)
    guard_registry: list[GuardRef] = Field(default_factory=list)
    coverage: Coverage = Field(default_factory=Coverage)
    config_public_routes: list[str] = Field(default_factory=list)
    config_auth_guards: list[str] = Field(default_factory=list)


class EvidenceStep(_Model):
    message: str
    loc: Loc | None = None


class TriageResult(_Model):
    decision: Literal["keep", "downgrade", "suppress"]  # never "add" or "upgrade"
    reason: str
    evidence_lines: list[Loc] = Field(default_factory=list)


Severity = Literal["critical", "high", "medium", "low"]
Tier = Literal["deterministic", "heuristic", "advisory", "verified"]


class Finding(_Model):
    rule_id: str
    fingerprint: str = ""
    severity: Severity
    tier: Tier
    title: str
    endpoint_id: str | None = None
    resource: str | None = None
    loc: Loc
    evidence: list[EvidenceStep] = Field(default_factory=list)
    explanation: str | None = None
    suggested_fix: str | None = None
    llm_triage: TriageResult | None = None
    delta: str = ""  # normalized delta facts, part of the fingerprint
