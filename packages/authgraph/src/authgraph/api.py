"""Stable entry points used by the CLI, the GitHub App and the eval harness."""

from __future__ import annotations

import re
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
    # Findings an LLM judge suppressed (reason in ``llm_triage``); counted in the check summary.
    suppressed: list[Finding] = field(default_factory=list)


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
    findings = [f for f in findings if not suppressed_inline(head, f)]
    findings.sort(key=lambda f: (SEVERITY_ORDER[f.severity], f.rule_id, f.endpoint_id or ""))
    return DiffResult(findings, b.facts, h.facts, cfg, cfg.errors + head_cfg.errors)


IGNORE_MARK = re.compile(r"accessguard-ignore(?:\[([A-Z0-9,\- ]+)\])?")


def suppressed_inline(tree: SourceTree, f: Finding) -> bool:
    """``# accessguard-ignore`` or ``# accessguard-ignore[AG-AUTH-001]`` on the finding's line or
    the line above it (FB: inline suppression, kept in the code under review)."""
    if not f.loc.path or f.loc.line < 1 or not tree.exists(f.loc.path):
        return False
    lines = tree.read(f.loc.path).decode("utf-8", "replace").splitlines()
    ln = f.loc.line - 1  # the finding's own line, then upward through decorators/comments
    while 0 <= ln < len(lines) and ln >= f.loc.line - 12:
        text = lines[ln].strip()
        if m := IGNORE_MARK.search(text):
            rules = m.group(1)
            return rules is None or f.rule_id in {r.strip() for r in rules.split(",")}
        in_block = text.startswith(("@", "#", ")", "]")) or text.endswith((",", "(", "["))
        if ln < f.loc.line - 1 and text and not in_block:
            return False  # left the decorator block
        ln -= 1
    return False


def diff_paths(base: Path | str, head: Path | str) -> list[dict[str, Any]]:
    """JSON-ready findings for two directories or git revisions (used by the eval harness)."""
    r = diff_trees(open_tree(base), open_tree(head))
    return [f.model_dump(mode="json") for f in r.findings]
