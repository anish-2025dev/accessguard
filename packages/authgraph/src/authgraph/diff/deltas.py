"""Base-vs-head fact diff (FR-3.5; PLAN.md §6.4 "Diff stage").

Endpoints are matched by id, falling back to handler identity for renamed paths. Every delta is a
deterministic fact about the two graphs; rules decide which deltas become findings.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from authgraph.diff.logic import weakened
from authgraph.facts.models import (
    ENFORCING_KINDS,
    Endpoint,
    FactGraph,
    GuardKind,
    GuardRef,
    Verdict,
)
from authgraph.guards.scoring import CONFIRMED

STRICT_FAIL = ("raise", "return_4xx")
SOFT_FAIL = ("log_only", "none")


@dataclass
class Delta:
    kind: str
    head: Endpoint
    base: Endpoint | None = None
    guard: GuardRef | None = None  # the base-side guard the delta is about
    head_guard: GuardRef | None = None
    detail: str = ""
    fields: list[str] = field(default_factory=list)


def enforcing(g: GuardRef) -> bool:
    return g.kind in ENFORCING_KINDS and g.confidence >= CONFIRMED


def guard_key(g: GuardRef) -> str:
    """Module-independent identity, so moving a guard to another file is not a removal."""
    return g.symbol.rsplit(".", 1)[-1]


def _short_handler(e: Endpoint) -> str:
    return f"{e.method} {e.handler.rsplit('.', 1)[-1]}"


def match(base: FactGraph, head: FactGraph) -> list[tuple[Endpoint | None, Endpoint | None]]:
    b_by_id = {e.id: e for e in base.endpoints}
    h_by_id = {e.id: e for e in head.endpoints}
    pairs: list[tuple[Endpoint | None, Endpoint | None]] = [
        (b_by_id[i], h) for i, h in h_by_id.items() if i in b_by_id
    ]
    b_rest = [e for i, e in b_by_id.items() if i not in h_by_id]
    h_rest = [e for i, e in h_by_id.items() if i not in b_by_id]
    b_handlers: dict[str, list[Endpoint]] = {}
    for e in b_rest:
        b_handlers.setdefault(_short_handler(e), []).append(e)
    used: set[str] = set()
    for h in h_rest:
        cands = b_handlers.get(_short_handler(h), [])
        if len(cands) == 1 and cands[0].id not in used:  # renamed path, same handler
            used.add(cands[0].id)
            pairs.append((cands[0], h))
        else:
            pairs.append((None, h))
    pairs += [(b, None) for b in b_rest if b.id not in used]
    return pairs


def _covers(head: Endpoint, removed: GuardRef) -> bool:
    """Does the head still enforce what the removed guard enforced?"""
    h_enf = [g for g in head.guards if enforcing(g)]
    if removed.kind == GuardKind.AUTHN:
        return bool(h_enf)
    return any(g.kind == removed.kind for g in h_enf)


def moved_into_new_guard(b: Endpoint, h: Endpoint, bg: GuardRef) -> bool:
    base_keys = {guard_key(g) for g in b.guards}
    return any(
        enforcing(g) and g.kind == bg.kind and guard_key(g) not in base_keys for g in h.guards
    )


def endpoint_deltas(b: Endpoint, h: Endpoint) -> list[Delta]:
    out: list[Delta] = []
    h_all: dict[str, list[GuardRef]] = {}
    for g in h.guards:
        h_all.setdefault(guard_key(g), []).append(g)
    for bg in (g for g in b.guards if enforcing(g)):
        same = h_all.get(guard_key(bg), [])
        hg = next((g for g in same if g.kind == bg.kind), same[0] if same else None)
        # "Neutered" is about one function body that stopped rejecting; library primitives
        # (two OAuth2PasswordBearer instances, one with auto_error=False) are distinct guards.
        neuterable = bg.source != "builtin"
        if neuterable and hg is not None and bg.on_fail in STRICT_FAIL and hg.on_fail in SOFT_FAIL:
            out.append(
                Delta(
                    "failure_neutered",
                    h,
                    b,
                    bg,
                    hg,
                    f"{bg.symbol}: on failure {bg.on_fail} -> {hg.on_fail}",
                )
            )
            continue
        if hg is None or not enforcing(hg) or hg.kind != bg.kind:
            # An unresolved head dependency may be the guard itself (moved, or a file that
            # no longer parses), so removal is only reported when the head is fully resolved.
            if not _covers(h, bg) and h.authn != Verdict.UNKNOWN and not h.unresolved:
                out.append(Delta("guard_removed", h, b, bg, hg, f"{bg.symbol} ({bg.kind})"))
            continue
        w = weakened(bg.condition, hg.condition)
        if w and moved_into_new_guard(b, h, bg):
            w = False  # the dropped clause now lives in a new guard of the same kind
        if w:
            out.append(
                Delta(
                    "condition_weakened",
                    h,
                    b,
                    bg,
                    hg,
                    f"{bg.symbol}: rejection condition is strictly weaker",
                )
            )
        if bg.dominates_sink and hg.dominates_sink is False:
            out.append(
                Delta(
                    "sink_before_check", h, b, bg, hg, f"{bg.symbol} now runs after the data access"
                )
            )
    has_owner = any(g.kind == GuardKind.AUTHZ_OWNER and enforcing(g) for g in h.guards)
    if not has_owner:
        # Multiset compare: the same model may be queried scoped and unscoped (admin branch).
        b_scoped = Counter((s.kind, s.model) for s in b.sinks if s.principal_scoped)
        h_scoped = Counter((s.kind, s.model) for s in h.sinks if s.principal_scoped)
        h_models = {(s.kind, s.model) for s in h.sinks}
        for (kind, model), n in (b_scoped - h_scoped).items():
            if (kind, model) in h_models:
                out.append(
                    Delta(
                        "scope_removed",
                        h,
                        b,
                        detail=f"{model} {kind} no longer "
                        f"filtered by the current user ({n} lookup(s))",
                    )
                )
    new_fields = sorted(set(h.mass_assign_fields) - set(b.mass_assign_fields))
    if new_fields:
        out.append(Delta("mass_assign", h, b, detail=", ".join(new_fields), fields=new_fields))
    if (
        h.authn == Verdict.NO_AUTH
        and h.mounted_under_auth
        and not b.mounted_under_auth
        and not out
        and not h.public_by_config
    ):
        out.append(Delta("mount_unguarded", h, b))
    return out


def new_endpoint_deltas(h: Endpoint) -> list[Delta]:
    out: list[Delta] = []
    if h.authn == Verdict.NO_AUTH and not h.public_by_config:
        out.append(Delta("mount_unguarded" if h.mounted_under_auth else "new_unguarded", h))
    if h.mass_assign_fields:
        out.append(
            Delta(
                "mass_assign",
                h,
                detail=", ".join(h.mass_assign_fields),
                fields=list(h.mass_assign_fields),
            )
        )
    return out


def diff(base: FactGraph, head: FactGraph) -> list[Delta]:
    out: list[Delta] = []
    for b, h in match(base, head):
        if h is None:
            continue
        out += endpoint_deltas(b, h) if b is not None else new_endpoint_deltas(h)
    return out
