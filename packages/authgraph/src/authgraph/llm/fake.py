"""Deterministic judge for tests and for running the triage pipeline without a model."""

from __future__ import annotations

from collections.abc import Callable

from authgraph.facts.models import Finding, TriageResult
from authgraph.llm.judge import ContextPack, Explanation, FunctionSlice, GuardClassification

Decide = Callable[[Finding, ContextPack], TriageResult]


def keep_all(f: Finding, c: ContextPack) -> TriageResult:
    return TriageResult(decision="keep", reason="fake judge keeps everything")


class FakeJudge:
    def __init__(
        self,
        decide: Decide = keep_all,
        classify: Callable[[FunctionSlice], GuardClassification] | None = None,
    ) -> None:
        self.decide = decide
        self.classify = classify
        self.seen: list[ContextPack] = []

    async def triage(self, finding: Finding, context: ContextPack) -> TriageResult:
        self.seen.append(context)
        return self.decide(finding, context)

    async def classify_guard(self, fn: FunctionSlice) -> GuardClassification:
        if self.classify is None:
            return GuardClassification(kind="not_a_guard", confidence=1.0, reason="fake")
        return self.classify(fn)

    async def explain(self, finding: Finding, context: ContextPack) -> Explanation:
        return Explanation(text=f"{finding.rule_id}: {finding.title}")
