"""AG-CFG-001: the PR widens ``public_routes`` or ``auth_guards`` (ADR 006).

The head config is never *applied*; it is only diffed against the base config so a PR that tries
to allowlist itself is reported.
"""

from __future__ import annotations

from collections.abc import Iterable

from authgraph.facts.models import EvidenceStep, FactGraph, Finding, Loc
from authgraph.guards.config import CONFIG_FILE
from authgraph.rules.base import RuleContext, finalize


class ConfigWidened:
    id = "AG-CFG-001"
    title = "Pull request widens AccessGuard configuration"
    default_severity = "medium"
    tier = "deterministic"

    def evaluate(
        self, head: FactGraph, base: FactGraph | None, ctx: RuleContext
    ) -> Iterable[Finding]:
        loc = Loc(path=CONFIG_FILE, line=1)
        base_routes = {r.route for r in ctx.base_config.public_routes}
        for r in ctx.head_config.public_routes:
            if r.route in base_routes:
                continue
            existing = next((e for e in head.endpoints if e.id == r.route), None)
            yield finalize(
                Finding(
                    rule_id=self.id,
                    severity="high" if existing else "medium",
                    tier="deterministic",
                    title=f"PR declares {r.route} public",
                    endpoint_id=r.route,
                    loc=loc,
                    delta="public_routes",
                    evidence=[
                        EvidenceStep(
                            message=f"public_routes gains {r.route!r} (reason: "
                            f"{r.reason or 'none given'})",
                            loc=loc,
                        ),
                        EvidenceStep(
                            message="configuration is read from the base branch, so this "
                            "takes effect only after merge"
                        ),
                    ],
                ),
                ctx,
            )
        base_guards = {g.symbol for g in ctx.base_config.auth_guards}
        for g in ctx.head_config.auth_guards:
            if g.symbol in base_guards:
                continue
            yield finalize(
                Finding(
                    rule_id=self.id,
                    severity="medium",
                    tier="deterministic",
                    title=f"PR declares {g.symbol} an auth guard ({g.kind})",
                    resource=g.symbol,
                    loc=loc,
                    delta="auth_guards",
                    evidence=[EvidenceStep(message=f"auth_guards gains {g.symbol!r}", loc=loc)],
                ),
                ctx,
            )
