"""Per-rule precision from hand-labelled history replays (PLAN.md §7 layer 2, Phase 3 exit gate).

Reads eval/reports/replay-<repo>.json and eval/corpus/labels/<repo>.yaml and prints, per rule:
findings, labelled TP / FP, precision (factual: is the reported access change real?), and for
inline (deterministic) findings how many a reviewer would act on. Replays cover merged history,
where most access changes are intentional, so "actionable" is a pessimistic proxy for the
product metric (effective FP = no positive action taken), which the pilot measures directly.

    python eval/tools/precision_table.py [--markdown]
"""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path

import yaml

EVAL = Path(__file__).resolve().parents[1]


def table() -> tuple[dict[str, dict[str, int]], dict[str, int]]:
    rules: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    repos: dict[str, int] = {}
    for report in sorted((EVAL / "reports").glob("replay-*.json")):
        name = report.stem.removeprefix("replay-")
        data = json.loads(report.read_text())
        labels_file = EVAL / "corpus" / "labels" / f"{name}.yaml"
        labels = (yaml.safe_load(labels_file.read_text()) if labels_file.exists() else None) or {}
        repos[name] = data["commits"]
        for f in data["items"]:
            r = rules[f["rule_id"]]
            lab = labels.get(f["fingerprint"])
            r["findings"] += 1
            if lab is None:
                r["unlabelled"] += 1
                continue
            r[lab["label"]] += 1
            if f["tier"] == "deterministic":
                r["inline"] += 1
                r["inline_actionable"] += bool(lab.get("actionable"))
                r["inline_fp"] += lab["label"] == "fp"
    return rules, repos


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--markdown", action="store_true")
    args = ap.parse_args()
    rules, repos = table()
    print(f"{len(repos)} repositories, {sum(repos.values())} commits replayed\n")
    head = "| Rule | Findings | TP | FP | Unlabelled | Precision | Inline | Inline FP |"
    print(head if args.markdown else head.replace("|", " "))
    if args.markdown:
        print("|---|---|---|---|---|---|---|---|")
    for rule in sorted(rules):
        r = rules[rule]
        labelled = r["tp"] + r["fp"]
        prec = f"{r['tp'] / labelled:.0%}" if labelled else "n/a"
        row = (
            f"| {rule} | {r['findings']} | {r['tp']} | {r['fp']} | {r['unlabelled']} | {prec} "
            f"| {r['inline']} | {r['inline_fp']} |"
        )
        print(row if args.markdown else row.replace("|", " "))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
