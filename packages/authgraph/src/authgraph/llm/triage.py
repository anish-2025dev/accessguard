"""Apply an LLM judge to engine findings without ever adding or upgrading one (ADR 004, 011).

* Only ``heuristic`` and ``advisory`` findings are triaged; ``deterministic`` ones are proven by
  the engine and at most get an explanation.
* IDOR judgements use ``samples`` (default 3) independent calls and a majority vote; ties keep.
* ``downgrade`` turns a heuristic finding into an advisory one; ``suppress`` removes it from the
  report but keeps it, with the judge's reason, in ``TriageOutcome.suppressed`` so the check
  summary can count and the log can record every suppression.
* Any judge error, timeout or malformed answer keeps the finding unchanged (fail-open).
"""

from __future__ import annotations

import asyncio
import logging
from collections import Counter
from dataclasses import dataclass, field

from authgraph.facts.models import Finding, Loc, TriageResult
from authgraph.llm.context import build_context, function_slice
from authgraph.llm.judge import GuardClassification, Judge
from authgraph.workspace.tree import SourceTree

log = logging.getLogger("authgraph.llm")

TRIAGED_TIERS = frozenset({"heuristic", "advisory"})
MAJORITY_RULES = ("AG-IDOR-",)
ALLOWED = frozenset({"keep", "downgrade", "suppress"})
CALL_TIMEOUT = 60.0


@dataclass
class TriageOutcome:
    kept: list[Finding]
    suppressed: list[Finding] = field(default_factory=list)
    downgraded: int = 0
    errors: int = 0


async def _one(judge: Judge, f: Finding, tree: SourceTree) -> TriageResult | None:
    try:
        r = await asyncio.wait_for(judge.triage(f, build_context(tree, f)), CALL_TIMEOUT)
    except Exception as e:
        log.warning("triage failed for %s: %s", f.fingerprint[:12], e)
        return None
    return r if r.decision in ALLOWED else None


async def triage_finding(
    judge: Judge, f: Finding, tree: SourceTree, samples: int
) -> TriageResult | None:
    n = samples if f.rule_id.startswith(MAJORITY_RULES) else 1
    results = [r for r in await asyncio.gather(*(_one(judge, f, tree) for _ in range(n))) if r]
    if not results:
        return None
    votes = Counter(r.decision for r in results)
    decision, count = votes.most_common(1)[0]
    if n > 1 and count <= n // 2:
        return TriageResult(decision="keep", reason="no majority among judge samples")
    return next(r for r in results if r.decision == decision)


async def apply_triage(
    findings: list[Finding], judge: Judge, tree: SourceTree, samples: int = 3
) -> TriageOutcome:
    out = TriageOutcome(kept=[])
    todo = [f for f in findings if f.tier in TRIAGED_TIERS]
    results = await asyncio.gather(*(triage_finding(judge, f, tree, samples) for f in todo))
    verdicts = {f.fingerprint: r for f, r in zip(todo, results, strict=True)}
    for f in findings:
        r = verdicts.get(f.fingerprint)
        if f.fingerprint in verdicts and r is None:
            out.errors += 1
        if r is None or r.decision == "keep":
            out.kept.append(f.model_copy(update={"llm_triage": r}) if r else f)
            continue
        if r.decision == "downgrade":
            out.downgraded += f.tier != "advisory"
            out.kept.append(f.model_copy(update={"tier": "advisory", "llm_triage": r}))
        else:
            log.info("suppressed %s %s: %s", f.rule_id, f.fingerprint[:12], r.reason)
            out.suppressed.append(f.model_copy(update={"llm_triage": r}))
    # Structural guarantee: the judge can only remove or relabel what the engine produced.
    if not {f.fingerprint for f in out.kept} <= {f.fingerprint for f in findings}:
        raise RuntimeError("triage produced a finding the engine did not")
    return out


async def explain_findings(
    findings: list[Finding], judge: Judge, tree: SourceTree, limit: int = 10
) -> list[Finding]:
    out: list[Finding] = []
    for i, f in enumerate(findings):
        if i >= limit or f.explanation:
            out.append(f)
            continue
        try:
            ex = await asyncio.wait_for(judge.explain(f, build_context(tree, f)), CALL_TIMEOUT)
        except Exception as e:
            log.warning("explain failed for %s: %s", f.fingerprint[:12], e)
            out.append(f)
            continue
        out.append(f.model_copy(update={"explanation": ex.text}))
    return out


@dataclass
class GuardSuggestion:
    symbol: str
    loc: Loc
    classification: GuardClassification


async def suggest_guards(
    candidates: list[tuple[str, Loc]], judge: Judge, tree: SourceTree, limit: int = 10
) -> list[GuardSuggestion]:
    """Ambiguous functions (scored below confirmation) -> suggestions for maintainers to
    confirm into ``auth_guards`` (FR-7.6). Nothing here changes a verdict or a finding."""
    out: list[GuardSuggestion] = []
    for symbol, loc in candidates[:limit]:
        sl = function_slice(tree, symbol, loc)
        if sl is None:
            continue
        try:
            c = await asyncio.wait_for(judge.classify_guard(sl), CALL_TIMEOUT)
        except Exception as e:
            log.warning("classify failed for %s: %s", symbol, e)
            continue
        if c.kind != "not_a_guard" and c.confidence >= 0.8:
            out.append(GuardSuggestion(symbol, loc, c))
    return out
