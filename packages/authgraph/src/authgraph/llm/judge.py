"""LLM judge interface (PLAN.md §6.13; ADR 004 "the deterministic engine is the only source of
findings").

The judge never sees anything but bounded, sanitised code slices, and it can only:

* ``triage``: keep, downgrade or suppress an existing finding (never add or upgrade one);
* ``classify_guard``: suggest how an ambiguous function should be classified; suggestions are
  shown to maintainers, who confirm them into ``.accessguard.yml`` (FR-7.6);
* ``explain``: write a short explanation for a finding the engine already produced.
"""

from __future__ import annotations

from typing import Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field

from authgraph.facts.models import Finding, Loc, TriageResult


class _M(BaseModel):
    model_config = ConfigDict(extra="forbid")


class CodeSlice(_M):
    path: str
    start_line: int
    text: str  # sanitised; never contains agent-instruction files or binary content


class ContextPack(_M):
    """What the judge may read about one finding: the finding's own facts plus code slices."""

    rule_id: str
    title: str
    evidence: list[str] = Field(default_factory=list)
    slices: list[CodeSlice] = Field(default_factory=list)


class FunctionSlice(_M):
    symbol: str
    loc: Loc
    code: CodeSlice


class GuardClassification(_M):
    kind: Literal["authn", "authz_role", "authz_owner", "optional_authn", "not_a_guard"]
    confidence: float = Field(ge=0.0, le=1.0)
    reason: str


class Explanation(_M):
    text: str = Field(max_length=1200)


class Judge(Protocol):
    async def triage(self, finding: Finding, context: ContextPack) -> TriageResult: ...
    async def classify_guard(self, fn: FunctionSlice) -> GuardClassification: ...
    async def explain(self, finding: Finding, context: ContextPack) -> Explanation: ...
