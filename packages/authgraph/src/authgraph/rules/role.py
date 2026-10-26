"""AG-ROLE-002: mass assignment of role/owner fields from the request body."""

from __future__ import annotations

from collections.abc import Iterable

from authgraph.facts.models import EvidenceStep, FactGraph, Finding
from authgraph.rules.base import RuleContext, finalize, route_evidence


class MassAssignment:
    """Fires when a request-body model whose privileged fields (role, is_superuser, owner_id,
    ...) is mass-assigned (``setattr`` loop over ``model_dump()``, ``Model(**body.dict())``,
    ``obj.sqlmodel_update(...)``) on an endpoint without a role guard, and the diff introduced
    those fields."""

    id = "AG-ROLE-002"
    title = "Privileged field mass-assigned from the request body"
    default_severity = "high"
    tier = "deterministic"

    def evaluate(
        self, head: FactGraph, base: FactGraph | None, ctx: RuleContext
    ) -> Iterable[Finding]:
        for d in ctx.deltas:
            if d.kind != "mass_assign":
                continue
            e = d.head
            fields = ", ".join(d.fields)
            yield finalize(
                Finding(
                    rule_id=self.id,
                    severity="high",
                    tier="deterministic",
                    title=f"{e.id} lets callers set {fields}",
                    endpoint_id=e.id,
                    loc=e.loc,
                    delta="mass_assign:" + ",".join(d.fields),
                    evidence=[
                        *route_evidence(e),
                        EvidenceStep(
                            message=f"request body fields copied onto the object include: {fields}"
                        ),
                    ],
                    suggested_fix="Remove the field from the request schema, or exclude it "
                    "(model_dump(exclude={...})) and set it server-side.",
                ),
                ctx,
            )
