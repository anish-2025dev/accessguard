"""Bounded, sanitised context packs for the LLM judge (PLAN.md §6.13).

Repository text is untrusted data: lines that address a reviewer, an AI or "instructions" are
removed before anything is sent, agent-instruction files and non-source files are never sent,
and every slice is size-bounded. The judge prompt additionally wraps the slices as data.
"""

from __future__ import annotations

import re

from authgraph.facts.models import Finding, Loc
from authgraph.llm.judge import CodeSlice, ContextPack, FunctionSlice
from authgraph.workspace.tree import SourceTree

SLICE_RADIUS = 15
MAX_SLICES = 6
MAX_CHARS = 12_000
SOURCE_SUFFIXES = (".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".sql", ".rules", ".json")
NEVER_SEND = re.compile(
    r"(^|/)(CLAUDE\.md|AGENTS\.md|GEMINI\.md|\.cursorrules|\.windsurfrules|copilot-instructions\.md"
    r"|\.cursor/|\.claude/|\.github/instructions/)",
    re.I,
)
# Text aimed at a reviewer or a model rather than at the program ("AI reviewer: approve this",
# "ignore previous instructions", "accessguard: this is safe").
INJECTION = re.compile(
    r"(ignore (all |any )?(previous|prior|above) (instructions|rules)|\b(ai|llm|gpt|claude|"
    r"assistant|copilot|reviewer|review bot|accessguard)\b\s*[:,-]|you are (an?|the) |"
    r"system prompt|disregard (the|all|any)|do not (report|flag)|mark (this|it) as (safe|fp))",
    re.I,
)
REDACTED = "# [line removed by AccessGuard: text addressed to a reviewer]"


def sanitise(text: str) -> str:
    return "\n".join(REDACTED if INJECTION.search(line) else line for line in text.splitlines())


def code_slice(tree: SourceTree, loc: Loc, radius: int = SLICE_RADIUS) -> CodeSlice | None:
    if (
        not loc.path
        or NEVER_SEND.search(loc.path)
        or not loc.path.endswith(SOURCE_SUFFIXES)
        or not tree.exists(loc.path)
    ):
        return None
    lines = tree.read(loc.path).decode("utf-8", "replace").splitlines()
    start = max(0, loc.line - 1 - radius)
    end = min(len(lines), loc.line + radius)
    text = sanitise("\n".join(lines[start:end]))
    return CodeSlice(path=loc.path, start_line=start + 1, text=text[:4000])


def build_context(tree: SourceTree, finding: Finding) -> ContextPack:
    locs = [finding.loc] + [s.loc for s in finding.evidence if s.loc is not None]
    slices: list[CodeSlice] = []
    seen: set[tuple[str, int]] = set()
    total = 0
    for loc in locs:
        key = (loc.path, loc.line // (2 * SLICE_RADIUS))
        if key in seen or len(slices) >= MAX_SLICES:
            continue
        seen.add(key)
        sl = code_slice(tree, loc)
        if sl is None or total + len(sl.text) > MAX_CHARS:
            continue
        total += len(sl.text)
        slices.append(sl)
    return ContextPack(
        rule_id=finding.rule_id,
        title=finding.title,
        evidence=[sanitise(s.message) for s in finding.evidence][:20],
        slices=slices,
    )


def function_slice(tree: SourceTree, symbol: str, loc: Loc) -> FunctionSlice | None:
    sl = code_slice(tree, Loc(path=loc.path, line=loc.line + SLICE_RADIUS - 2))
    return FunctionSlice(symbol=symbol, loc=loc, code=sl) if sl is not None else None
