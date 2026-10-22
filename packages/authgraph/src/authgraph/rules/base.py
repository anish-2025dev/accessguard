"""Rule interface (PLAN.md §6.5) and fingerprints (§6.6)."""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Protocol

from authgraph.diff.deltas import Delta
from authgraph.facts.models import Endpoint, EvidenceStep, FactGraph, Finding
from authgraph.guards.config import Config


def fingerprint(rule_id: str, repo_id: str, subject: str, delta: str) -> str:
    """Line numbers are excluded so moved code never resurfaces as a new finding."""
    raw = "|".join([rule_id, repo_id, subject, delta])
    return hashlib.sha256(raw.encode()).hexdigest()


@dataclass
class RuleContext:
    repo_id: str = ""
    base_config: Config = field(default_factory=Config)
    head_config: Config = field(default_factory=Config)  # data only: diffed for AG-CFG-001
    deltas: list[Delta] = field(default_factory=list)


class Rule(Protocol):
    id: str
    title: str
    default_severity: str
    tier: str

    def evaluate(
        self, head: FactGraph, base: FactGraph | None, ctx: RuleContext
    ) -> Iterable[Finding]: ...


def route_evidence(e: Endpoint) -> list[EvidenceStep]:
    steps = [EvidenceStep(message=f"{e.id} is handled by {e.handler}", loc=e.loc)]
    steps += [EvidenceStep(message="included/mounted here", loc=loc) for loc in e.chain]
    return steps


def finalize(f: Finding, ctx: RuleContext) -> Finding:
    subject = f.endpoint_id or f.resource or ""
    f.fingerprint = fingerprint(f.rule_id, ctx.repo_id, subject, f.delta)
    return f
