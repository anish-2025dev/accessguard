"""AG-ROLE-001: sensitive endpoint lacks a role check that its peers have (FR-3.4; PLAN.md §6.4).

Peer-group consistency in the style of Engler et al., "Bugs as Deviant Behavior" (SOSP 2001):
peers are the other endpoints of the same router with the same verb class. For each role atom
(an enforcing ``authz_role`` guard, by name) held by ``e`` of the ``n`` peers,

    z = (e/n - p0) / sqrt(p0 (1 - p0) / n),   p0 = 0.9,   n >= 4

and a new or changed endpoint that lacks an atom with ``z >= 0`` (at least 90% of four or more
peers hold it) is reported, ranked by ``z``. Absolute fallback: a new mutating endpoint under an
``admin`` path that is authenticated but has no role check at all, whatever its peers do.

Only endpoints introduced or changed by the diff are reported, only when they are AUTH (an
unauthenticated one is AG-AUTH-001's), and never when AG-AUTH-002 already reports the same
endpoint for a removed role guard.
"""

from __future__ import annotations

import math
from collections import defaultdict
from collections.abc import Iterable

from authgraph.diff.deltas import enforcing, guard_key
from authgraph.facts.models import (
    Endpoint,
    EvidenceStep,
    FactGraph,
    Finding,
    GuardKind,
    Verdict,
)
from authgraph.rules.auth import MUTATING
from authgraph.rules.base import RuleContext, finalize, route_evidence

P0 = 0.9
MIN_PEERS = 4


def role_atoms(e: Endpoint) -> set[str]:
    return {guard_key(g) for g in e.guards if g.kind == GuardKind.AUTHZ_ROLE and enforcing(g)}


def z_score(e: int, n: int, p0: float = P0) -> float:
    return (e / n - p0) / math.sqrt(p0 * (1 - p0) / n)


def verb_class(method: str) -> str:
    return "write" if method in MUTATING else "read"


class RoleConsistency:
    id = "AG-ROLE-001"
    title = "Endpoint lacks the role check its peers have"
    default_severity = "high"
    tier = "heuristic"

    def evaluate(
        self, head: FactGraph, base: FactGraph | None, ctx: RuleContext
    ) -> Iterable[Finding]:
        base_by_id = {e.id: e for e in (base.endpoints if base else [])}
        reported_by_002 = {
            d.head.id
            for d in ctx.deltas
            if d.kind in {"guard_removed", "guard_reordered"}
            and d.guard is not None
            and d.guard.kind == GuardKind.AUTHZ_ROLE
        }
        groups: dict[tuple[str, str], list[Endpoint]] = defaultdict(list)
        for e in head.endpoints:
            groups[(e.router_group, verb_class(e.method))].append(e)
        for e in head.endpoints:
            if e.authn != Verdict.AUTH or e.public_by_config or e.id in reported_by_002:
                continue
            b = base_by_id.get(e.id)
            mine = role_atoms(e)
            if b is not None and role_atoms(b) == mine:
                continue  # unchanged with respect to roles: not introduced by this diff
            peers = [p for p in groups[(e.router_group, verb_class(e.method))] if p.id != e.id]
            best: tuple[float, str, int, int] | None = None
            if len(peers) >= MIN_PEERS:
                counts: dict[str, int] = defaultdict(int)
                for p in peers:
                    for atom in role_atoms(p):
                        counts[atom] += 1
                for atom, k in counts.items():
                    if atom in mine:
                        continue
                    z = z_score(k, len(peers))
                    if z >= 0 and (best is None or z > best[0]):
                        best = (z, atom, k, len(peers))
            if best is not None:
                z, atom, k, n = best
                yield self._finding(
                    e,
                    ctx,
                    f"{k} of {n} peer endpoints on this router require `{atom}` (z = {z:.2f})",
                    f"missing:{atom}",
                    "high" if "admin_path" in e.sensitivity or e.method in MUTATING else "medium",
                )
            elif b is None and not mine and e.method in MUTATING and "admin_path" in e.sensitivity:
                yield self._finding(
                    e,
                    ctx,
                    "new state-changing endpoint under an admin path checks authentication only",
                    "admin_without_role",
                    "high",
                )

    def _finding(
        self, e: Endpoint, ctx: RuleContext, why: str, delta: str, severity: str
    ) -> Finding:
        return finalize(
            Finding(
                rule_id=self.id,
                severity="high" if severity == "high" else "medium",
                tier="heuristic",
                title=f"{e.id} has no role check its peers have",
                endpoint_id=e.id,
                loc=e.loc,
                delta=delta,
                evidence=[*route_evidence(e), EvidenceStep(message=why)],
                suggested_fix="Add the same role dependency/middleware as the neighbouring "
                "endpoints, or record why this one is different in .accessguard.yml.",
            ),
            ctx,
        )
