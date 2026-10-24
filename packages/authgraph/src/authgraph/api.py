"""Stable entry points used by the CLI, the GitHub App and the eval harness."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from authgraph.cache.summaries import SummaryCache, default_cache
from authgraph.diff.deltas import diff
from authgraph.engine import Analysis, analyze, read_config
from authgraph.facts.models import FactGraph, Finding
from authgraph.guards.config import Config
from authgraph.rules import ALL_RULES, RuleContext
from authgraph.workspace.tree import SourceTree, open_tree

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


@dataclass
class DiffResult:
    findings: list[Finding]
    base: FactGraph
    head: FactGraph
    config: Config  # the base-branch config that was applied
    config_errors: list[str] = field(default_factory=list)


def scan(tree: SourceTree, config: Config | None = None) -> Analysis:
    return analyze(tree, config)


def diff_trees(
    base: SourceTree,
    head: SourceTree,
    repo_id: str = "",
    cache: SummaryCache | None = None,
    base_config: Config | None = None,
) -> DiffResult:
    """Findings introduced by ``head`` relative to ``base``.

    Config comes from the BASE tree only (ADR 006); the head config is parsed solely to report
    widening (AG-CFG-001).
    """
    cache = cache or default_cache()
    cfg = base_config if base_config is not None else read_config(base)
    head_cfg = read_config(head)
    b = analyze(base, cfg, cache)
    h = analyze(head, cfg, cache)
    ctx = RuleContext(
        repo_id=repo_id, base_config=cfg, head_config=head_cfg, deltas=diff(b.facts, h.facts)
    )
    findings: list[Finding] = []
    seen: set[str] = set()
    for rule in ALL_RULES:
        if not cfg.rule_enabled(rule.id):
            continue
        for f in rule.evaluate(h.facts, b.facts, ctx):
            if f.fingerprint not in seen:
                seen.add(f.fingerprint)
                findings.append(f)
    findings.sort(key=lambda f: (SEVERITY_ORDER[f.severity], f.rule_id, f.endpoint_id or ""))
    return DiffResult(findings, b.facts, h.facts, cfg, cfg.errors + head_cfg.errors)


def diff_paths(base: Path | str, head: Path | str) -> list[dict[str, Any]]:
    """JSON-ready findings for two directories or git revisions (used by the eval harness)."""
    r = diff_trees(open_tree(base), open_tree(head))
    return [f.model_dump(mode="json") for f in r.findings]
