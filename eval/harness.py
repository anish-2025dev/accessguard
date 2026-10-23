"""AccessGuard evaluation harness (PLAN.md §7).

Runs every labelled case through ``authgraph.api.diff_paths`` and reports per-rule precision and
recall, the pure-move finding count, and (optionally) a regression check against a baseline report.

    python eval/harness.py                          # run, write eval/reports/report.{json,md}
    python eval/harness.py --baseline main.json     # also fail if any rule regressed vs baseline
    python eval/harness.py --enforce-gates          # also fail if eval/gates.yaml thresholds miss
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from authgraph.api import diff_paths

EVAL_DIR = Path(__file__).resolve().parent
CASE_DIRS = [EVAL_DIR / "mutations", EVAL_DIR / "pairs"]


@dataclass
class Case:
    id: str
    kind: str  # positive | negative | move
    root: Path
    expected: list[tuple[str, str]]


@dataclass
class RuleStats:
    tp: int = 0
    fp: int = 0
    fn: int = 0
    cases: set[str] = field(default_factory=set)

    @property
    def precision(self) -> float | None:
        return self.tp / (self.tp + self.fp) if self.tp + self.fp else None

    @property
    def recall(self) -> float | None:
        return self.tp / (self.tp + self.fn) if self.tp + self.fn else None


def load_cases(dirs: list[Path] = CASE_DIRS) -> list[Case]:
    cases = []
    for d in dirs:
        if not d.is_dir():
            continue
        for spec in sorted(d.glob("*/case.yaml")):
            data = yaml.safe_load(spec.read_text(encoding="utf-8"))
            expected = [(e["rule_id"], str(e["key"])) for e in data.get("expected") or []]
            cases.append(Case(data["id"], data["kind"], spec.parent, expected))
    return cases


def finding_key(f: dict[str, Any]) -> tuple[str, str]:
    return (f["rule_id"], str(f.get("endpoint_id") or f.get("resource") or f.get("key") or ""))


def evaluate(cases: list[Case]) -> dict[str, Any]:
    stats: dict[str, RuleStats] = {}
    move_findings = 0
    per_case = []
    for case in cases:
        got = Counter(finding_key(f) for f in diff_paths(case.root / "base", case.root / "head"))
        want = Counter(case.expected)
        for (rule, _), n in (got & want).items():
            stats.setdefault(rule, RuleStats()).tp += n
        for (rule, _), n in (got - want).items():
            stats.setdefault(rule, RuleStats()).fp += n
        for (rule, _), n in (want - got).items():
            stats.setdefault(rule, RuleStats()).fn += n
        for rule, _ in {*got, *want}:
            stats.setdefault(rule, RuleStats()).cases.add(case.id)
        if case.kind == "move":
            move_findings += sum(got.values())
        per_case.append(
            {
                "id": case.id,
                "kind": case.kind,
                "ok": got == want,
                "missing": sorted(f"{r} {k}" for r, k in (want - got)),
                "unexpected": sorted(f"{r} {k}" for r, k in (got - want)),
            }
        )
    return {
        "rules": {
            rule: {
                "tp": s.tp,
                "fp": s.fp,
                "fn": s.fn,
                "precision": s.precision,
                "recall": s.recall,
                "cases": len(s.cases),
            }
            for rule, s in sorted(stats.items())
        },
        "pure_move_findings": move_findings,
        "cases": per_case,
        "cases_passed": sum(c["ok"] for c in per_case),
        "cases_total": len(per_case),
    }


def _fmt(x: float | None) -> str:
    return "n/a" if x is None else f"{x:.0%}"


def to_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# AccessGuard eval report",
        "",
        f"Cases passed: {report['cases_passed']}/{report['cases_total']}  ",
        f"Pure-move findings: {report['pure_move_findings']}",
        "",
        "| Rule | TP | FP | FN | Precision | Recall |",
        "|---|---|---|---|---|---|",
    ]
    for rule, r in report["rules"].items():
        lines.append(
            f"| {rule} | {r['tp']} | {r['fp']} | {r['fn']} | "
            f"{_fmt(r['precision'])} | {_fmt(r['recall'])} |"
        )
    failed = [c for c in report["cases"] if not c["ok"]]
    if failed:
        lines += ["", "## Failing cases", ""]
        for c in failed:
            lines.append(
                f"- `{c['id']}` missing={c['missing'] or '-'} unexpected={c['unexpected'] or '-'}"
            )
    return "\n".join(lines) + "\n"


def regressions(report: dict[str, Any], baseline: dict[str, Any]) -> list[str]:
    """Rules whose precision or recall dropped versus the baseline (PLAN.md §4 eval gate)."""
    out = []
    for rule, base in baseline.get("rules", {}).items():
        cur = report["rules"].get(rule)
        for metric in ("precision", "recall"):
            b = base.get(metric)
            c = None if cur is None else cur.get(metric)
            if b is not None and (c is None or c < b - 1e-9):
                out.append(f"{rule} {metric}: {_fmt(b)} -> {_fmt(c)}")
    if report["pure_move_findings"] > baseline.get("pure_move_findings", 0):
        out.append(
            f"pure_move_findings: {baseline.get('pure_move_findings', 0)} -> "
            f"{report['pure_move_findings']}"
        )
    return out


def gate_failures(report: dict[str, Any], gates: dict[str, Any]) -> list[str]:
    out = []
    det = set(gates.get("deterministic_rules", []))
    for rule, r in report["rules"].items():
        if rule in det and r["precision"] is not None and r["precision"] < gates["min_precision"]:
            out.append(f"{rule} precision {_fmt(r['precision'])} < {_fmt(gates['min_precision'])}")
        if r["recall"] is not None and r["recall"] < gates["min_recall"]:
            out.append(f"{rule} recall {_fmt(r['recall'])} < {_fmt(gates['min_recall'])}")
    if report["pure_move_findings"] > gates.get("max_pure_move_findings", 0):
        out.append(f"pure-move findings {report['pure_move_findings']} > 0")
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, default=EVAL_DIR / "reports")
    ap.add_argument("--baseline", type=Path)
    ap.add_argument("--enforce-gates", action="store_true")
    args = ap.parse_args(argv)

    report = evaluate(load_cases())
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    md = to_markdown(report)
    (args.out / "report.md").write_text(md, encoding="utf-8")
    sys.stdout.write(md)

    problems: list[str] = []
    if args.baseline and args.baseline.exists():
        problems += regressions(report, json.loads(args.baseline.read_text(encoding="utf-8")))
    if args.enforce_gates:
        gates = yaml.safe_load((EVAL_DIR / "gates.yaml").read_text(encoding="utf-8"))
        problems += gate_failures(report, gates)
    for p in problems:
        sys.stdout.write(f"GATE FAIL: {p}\n")
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
