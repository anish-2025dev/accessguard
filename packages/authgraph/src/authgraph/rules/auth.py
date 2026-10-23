"""AG-AUTH-001/002/003: missing and regressed authentication (FR-3.2, FR-3.5)."""

from __future__ import annotations

import re
from collections.abc import Iterable

from authgraph.diff.deltas import Delta
from authgraph.facts.models import Endpoint, EvidenceStep, FactGraph, Finding, Severity, Verdict
from authgraph.rules.base import RuleContext, finalize, route_evidence

MUTATING = frozenset({"POST", "PUT", "PATCH", "DELETE"})
# Endpoints that are unauthenticated by design. A new one is not a regression on its own.
AUTH_FLOW = re.compile(
    r"/(login|logout|signin|sign-in|signup|sign-up|register|token|refresh|password|"
    r"reset|recover|forgot|verify|confirm|callback|oauth|webhooks?|health|healthz|"
    r"readyz|livez|status|ping|public|openapi|docs|auth)\b",
    re.I,
)
# `POST /users` with no auth is the signup convention; privileged fields in its body are still
# reported by AG-ROLE-002.
SIGNUP = re.compile(r"/(users?|accounts?|members?)/?$", re.I)
AUTH_FLOW_HANDLER = re.compile(
    r"^(login|logout|sign_?in|sign_?up|register|register_user|create_access_token|"
    r"refresh_token|forgot_password|reset_password|verify_email|webhook|health|healthcheck)",
    re.I,
)
REGRESSION_DELTAS = (
    "guard_removed",
    "guard_reordered",
    "condition_weakened",
    "failure_neutered",
    "sink_before_check",
    "scope_removed",
)


def _severity(e: Endpoint, base: Severity = "high") -> Severity:
    if {"admin_path", "delete"} & e.sensitivity:
        return "critical"
    return base


class NewUnauthenticatedEndpoint:
    """AG-AUTH-001: new endpoint is NO_AUTH and not public by config.

    Fires for mutating methods, or when the endpoint's router peers are authenticated
    (PLAN.md §6.4 ``new_unguarded``); auth-flow paths (login, signup, webhooks, health) are
    unauthenticated by design and skipped.
    """

    id = "AG-AUTH-001"
    title = "New endpoint has no authentication"
    default_severity = "high"
    tier = "deterministic"

    def evaluate(
        self, head: FactGraph, base: FactGraph | None, ctx: RuleContext
    ) -> Iterable[Finding]:
        peers_auth: dict[str, bool] = {}
        for e in head.endpoints:
            if e.authn == Verdict.AUTH:
                peers_auth[e.router_group] = True
        for d in ctx.deltas:
            if d.kind != "new_unguarded":
                continue
            e = d.head
            if AUTH_FLOW.search(e.path) or AUTH_FLOW_HANDLER.search(e.handler.rsplit(".", 1)[-1]):
                continue
            if e.method == "POST" and SIGNUP.search(e.path):
                continue
            if e.method not in MUTATING and not peers_auth.get(e.router_group):
                continue
            # Reads next to authenticated peers are often public by design (ADR 009): they go to
            # the check summary (advisory) unless the path is administrative.
            inline = e.method in MUTATING or "admin_path" in e.sensitivity
            yield finalize(
                Finding(
                    rule_id=self.id,
                    severity=_severity(e) if inline else "low",
                    tier="deterministic" if inline else "advisory",
                    title=f"{e.id} is reachable without authentication",
                    endpoint_id=e.id,
                    loc=e.loc,
                    delta="new_unguarded",
                    evidence=[
                        *route_evidence(e),
                        EvidenceStep(
                            message="no authentication dependency on the app, routers, "
                            "include_router(dependencies=...), decorator or parameters"
                        ),
                    ],
                    suggested_fix="Add an auth dependency (e.g. Depends(get_current_user)) or, if "
                    "the route is intentionally public, list it under public_routes in "
                    ".accessguard.yml on the base branch.",
                ),
                ctx,
            )


class GuardRegression:
    """AG-AUTH-002: guard removed, weakened, neutered, moved after the sink, or scope dropped."""

    id = "AG-AUTH-002"
    title = "Access check removed or weakened"
    default_severity = "high"
    tier = "deterministic"

    def evaluate(
        self, head: FactGraph, base: FactGraph | None, ctx: RuleContext
    ) -> Iterable[Finding]:
        by_ep: dict[str, list[Delta]] = {}
        for d in ctx.deltas:
            if d.kind in REGRESSION_DELTAS:
                by_ep.setdefault(d.head.id, []).append(d)
        for ep_id, ds in sorted(by_ep.items()):
            e = ds[0].head
            if AUTH_FLOW.search(e.path) or AUTH_FLOW_HANDLER.search(e.handler.rsplit(".", 1)[-1]):
                continue  # login/signup/token endpoints authenticate the caller by design
            steps = route_evidence(e)
            for d in ds:
                where = d.guard.loc if d.guard else None
                if d.guard and d.guard.inherited_from:
                    steps.append(
                        EvidenceStep(
                            message=f"base: {d.guard.symbol} was inherited from here",
                            loc=d.guard.inherited_from,
                        )
                    )
                steps.append(EvidenceStep(message=f"{d.kind}: {d.detail}", loc=where))
            kinds = sorted({d.kind for d in ds})
            keys = sorted({d.guard.symbol.rsplit(".", 1)[-1] for d in ds if d.guard})
            yield finalize(
                Finding(
                    rule_id=self.id,
                    severity=_severity(e),
                    tier="deterministic",
                    title=f"{ep_id}: " + ", ".join(k.replace("_", " ") for k in kinds),
                    endpoint_id=ep_id,
                    loc=e.loc,
                    evidence=steps,
                    delta=";".join(kinds + keys),
                    suggested_fix="Restore the removed or weakened check, or confirm the change "
                    "is intended and dismiss with `@accessguard ignore <reason>`.",
                ),
                ctx,
            )


class MountedWithoutAuth:
    """AG-AUTH-003: mounted sub-app does not inherit the parent's auth dependencies."""

    id = "AG-AUTH-003"
    title = "Mounted sub-application bypasses app-level authentication"
    default_severity = "high"
    tier = "deterministic"

    def evaluate(
        self, head: FactGraph, base: FactGraph | None, ctx: RuleContext
    ) -> Iterable[Finding]:
        for d in ctx.deltas:
            if d.kind == "registered_before_auth" and not AUTH_FLOW.search(d.head.path):
                yield self._before_auth(d, ctx)
                continue
            if d.kind != "mount_unguarded" or AUTH_FLOW.search(d.head.path):
                continue
            e = d.head
            yield finalize(
                Finding(
                    rule_id=self.id,
                    severity=_severity(e),
                    tier="deterministic",
                    title=f"{e.id} is on a mounted app that skips the parent app's auth",
                    endpoint_id=e.id,
                    loc=e.loc,
                    delta="mount_unguarded",
                    evidence=[
                        *route_evidence(e),
                        EvidenceStep(
                            message="app.mount() sub-applications do not inherit "
                            "FastAPI(dependencies=...) of the parent app"
                        ),
                    ],
                    suggested_fix="Use include_router() instead of mount(), or give the "
                    "sub-application its own dependencies=[Depends(...)].",
                ),
                ctx,
            )

    def _before_auth(self, d: Delta, ctx: RuleContext) -> Finding:
        e = d.head
        g = d.guard
        return finalize(
            Finding(
                rule_id=self.id,
                severity=_severity(e),
                tier="deterministic",
                title=f"{e.id} is registered before the auth middleware that covers its path",
                endpoint_id=e.id,
                loc=e.loc,
                delta="registered_before_auth",
                evidence=[
                    *route_evidence(e),
                    EvidenceStep(
                        message=f"{g.symbol if g else 'auth middleware'} is registered later; "
                        "Express runs middleware in registration order, so it never runs for "
                        "this route",
                        loc=g.loc if g else None,
                    ),
                ],
                suggested_fix="Register the route after the auth middleware, or add the guard "
                "to the route itself.",
            ),
            ctx,
        )
