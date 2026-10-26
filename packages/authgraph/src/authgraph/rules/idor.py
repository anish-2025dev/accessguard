"""AG-IDOR-001/002: object-level authorization (BOLA / IDOR) candidates (FR-3.3; PLAN.md §6.4).

A request id (path parameter, or a handler parameter named like an id) is traced through the
handler and its local callees (depth 4) to ORM sinks. Then, for an authenticated endpoint
without a role or ownership guard:

* AG-IDOR-001 (heuristic, high tier): the id reaches a sink and **no principal symbol** exists
  anywhere in the handler or the callees on the way: any logged-in user can address any object.
* AG-IDOR-002 (advisory): a principal is available but is neither part of the sink predicate nor
  compared with the fetched object. Whether the code elsewhere covers the same object is a
  judgement call, so these are advisory and go to the LLM judge, which may only keep, downgrade
  or suppress them (ADR 004).

Only endpoints that are new, or that did not qualify on the base side, are reported.
"""

from __future__ import annotations

from collections.abc import Iterable

from authgraph.diff.deltas import enforcing
from authgraph.facts.models import (
    Endpoint,
    EvidenceStep,
    FactGraph,
    Finding,
    GuardKind,
    Severity,
    Sink,
    Verdict,
)
from authgraph.rules.base import RuleContext, finalize, route_evidence

OBJECT_GUARDS = frozenset({GuardKind.AUTHZ_OWNER, GuardKind.AUTHZ_ROLE})


def _exposed_sinks(e: Endpoint, public_models: frozenset[str] = frozenset()) -> list[Sink]:
    """Sinks addressed by a request id and not scoped to the principal, when nothing on the
    endpoint checks object ownership or restricts it to a role. Models listed under
    ``public_models`` in the base config are intentionally public (PLAN.md §6.11)."""
    if e.authn != Verdict.AUTH or e.public_by_config or e.owner_check:
        return []
    if any(g.kind in OBJECT_GUARDS and enforcing(g) for g in e.guards):
        return []
    return [
        s
        for s in e.sinks
        if s.id_param
        and not s.principal_scoped
        and (s.model or "").rsplit(".", 1)[-1] not in public_models
    ]


def idor_tier(e: Endpoint, public_models: frozenset[str] = frozenset()) -> str | None:
    """IDOR tier: "high" (no principal at all), "medium" (principal not tied to the object)."""
    if not _exposed_sinks(e, public_models):
        return None
    return "medium" if e.principals else "high"


def _severity(sinks: list[Sink], high: bool) -> Severity:
    if any(s.kind != "read" for s in sinks):
        return "high" if high else "medium"
    return "medium" if high else "low"


class _IdorRule:
    id = ""
    tier_name = ""
    title = ""
    default_severity = "medium"
    tier = ""

    def evaluate(
        self, head: FactGraph, base: FactGraph | None, ctx: RuleContext
    ) -> Iterable[Finding]:
        base_by_id = {e.id: e for e in (base.endpoints if base else [])}
        regressed = {
            d.head.id
            for d in ctx.deltas
            if d.kind in {"scope_removed", "guard_removed", "condition_weakened"}
        }
        public = frozenset(ctx.base_config.public_models)
        for e in head.endpoints:
            if idor_tier(e, public) != self.tier_name or e.id in regressed:
                continue
            b = base_by_id.get(e.id)
            if b is not None and idor_tier(b, public) is not None:
                continue  # already exposed on the base branch: not introduced by this diff
            yield self.finding(e, ctx, public)

    def finding(self, e: Endpoint, ctx: RuleContext, public: frozenset[str]) -> Finding:
        sinks = _exposed_sinks(e, public)
        steps = route_evidence(e)
        for s in sinks[:3]:
            steps.append(
                EvidenceStep(
                    message=f"request id `{s.id_param}` selects {s.model or 'an object'} "
                    f"({s.orm}, {s.kind}) with no principal in the predicate",
                    loc=s.loc,
                )
            )
        steps.append(EvidenceStep(message=self.why(e)))
        models = sorted({f"{s.model}:{s.kind}" for s in sinks})
        return finalize(
            Finding(
                rule_id=self.id,
                severity=_severity(sinks, self.tier_name == "high"),
                tier="heuristic" if self.tier_name == "high" else "advisory",
                title=f"{e.id}: {self.title}",
                endpoint_id=e.id,
                loc=e.loc,
                evidence=steps,
                delta=";".join(models),
                suggested_fix="Filter the lookup by the current user (or tenant), or compare the "
                "fetched object's owner with the current user before using it.",
            ),
            ctx,
        )

    def why(self, e: Endpoint) -> str:
        raise NotImplementedError


class IdorNoPrincipal(_IdorRule):
    """AG-IDOR-001: id reaches a sink and no principal exists in the handler or its callees."""

    id = "AG-IDOR-001"
    tier_name = "high"
    title = "object fetched by request id with no user context"
    tier = "heuristic"

    def why(self, e: Endpoint) -> str:
        return (
            "the handler and its callees never use the authenticated user, so any user can "
            "address any object by id"
        )


class IdorPrincipalNotTied(_IdorRule):
    """AG-IDOR-002: principal available but not tied to the fetched object (advisory)."""

    id = "AG-IDOR-002"
    tier_name = "medium"
    title = "object fetched by request id is not tied to the current user"
    tier = "advisory"

    def why(self, e: Endpoint) -> str:
        return (
            f"`{', '.join(e.principals)}` is available but is not in the lookup predicate and "
            "is not compared with the fetched object"
        )
