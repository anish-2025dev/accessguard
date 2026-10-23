"""Triage true-positive retention (PLAN.md §3 Phase 3 exit gate: >= 96%).

Every expected (true-positive) finding of the eval mutation cases, plus every replay finding
labelled ``tp`` in eval/corpus/labels, is sent through ``apply_triage`` with the chosen judge.
Retention = TPs still reported (kept or downgraded) / TPs triaged. Replay findings labelled
``fp`` give the share of false positives the judge removes. Deterministic findings are never
triaged, so only heuristic and advisory TPs enter the denominator.

    python eval/tools/triage_eval.py                       # FakeJudge (keeps all): pipeline check
    python eval/tools/triage_eval.py --model anthropic/claude-sonnet-5-5   # needs authgraph[llm]
"""

from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path

import yaml
from authgraph.api import diff_trees
from authgraph.facts.models import Finding
from authgraph.llm.fake import FakeJudge
from authgraph.llm.judge import Judge
from authgraph.llm.triage import TRIAGED_TIERS, apply_triage
from authgraph.workspace.tree import DirectoryTree, GitTree

EVAL = Path(__file__).resolve().parents[1]


def _judge(model: str | None) -> Judge:
    if not model:
        return FakeJudge()
    from authgraph.llm.litellm_judge import LiteLLMJudge

    return LiteLLMJudge(model)


async def mutation_tps(judge: Judge) -> tuple[int, int]:
    kept = total = 0
    for case in sorted((EVAL / "mutations").iterdir()):
        spec_file = case / "case.yaml"
        if not spec_file.exists():
            continue
        want = {(e["rule_id"], e["key"]) for e in yaml.safe_load(spec_file.read_text())["expected"]}
        head = DirectoryTree(case / "head")
        r = diff_trees(DirectoryTree(case / "base"), head)
        tps = [
            f
            for f in r.findings
            if (f.rule_id, f.endpoint_id or f.resource) in want and f.tier in TRIAGED_TIERS
        ]
        if not tps:
            continue
        out = await apply_triage(tps, judge, head)
        kept += len(out.kept)
        total += len(tps)
    return kept, total


async def replay_labels(judge: Judge) -> dict[str, tuple[int, int]]:
    """label -> (still reported, triaged) for labelled replay findings, triaged at their commit."""
    res: dict[str, list[int]] = {"tp": [0, 0], "fp": [0, 0]}
    for lf in sorted((EVAL / "corpus" / "labels").glob("*.yaml")):
        name = lf.stem
        labels = yaml.safe_load(lf.read_text()) or {}
        report = EVAL / "reports" / f"replay-{name}.json"
        repo = EVAL / "corpus" / "checkouts" / name
        if not report.exists() or not repo.is_dir():
            continue
        for item in json.loads(report.read_text())["items"]:
            lab = labels.get(item["fingerprint"])
            if not lab or item.get("tier") not in TRIAGED_TIERS:
                continue
            f = Finding.model_validate({k: v for k, v in item.items() if k in Finding.model_fields})
            out = await apply_triage([f], judge, GitTree(repo, item["commit"]))
            res[lab["label"]][0] += len(out.kept)
            res[lab["label"]][1] += 1
    return {k: (v[0], v[1]) for k, v in res.items()}


async def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", help="LiteLLM model name; omitted = FakeJudge")
    ap.add_argument("--min-retention", type=float, default=0.96)
    args = ap.parse_args()
    judge = _judge(args.model)
    kept, total = await mutation_tps(judge)
    rep = await replay_labels(judge)
    tp_kept, tp_total = kept + rep["tp"][0], total + rep["tp"][1]
    fp_kept, fp_total = rep["fp"]
    retention = tp_kept / tp_total if tp_total else 1.0
    print(f"judge: {args.model or 'FakeJudge (keeps all)'}")
    print(
        f"TP retention: {tp_kept}/{tp_total} = {retention:.1%} (gate >= {args.min_retention:.0%})"
    )
    if fp_total:
        print(f"FP removed: {fp_total - fp_kept}/{fp_total}")
    return 0 if retention >= args.min_retention else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
