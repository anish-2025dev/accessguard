"""Replay a corpus repo's real history through ``authgraph diff`` (real-world precision check).

Every commit that touches Python or .accessguard.yml is diffed against its first parent, as a push
would be. Findings are written to eval/reports/replay-<name>.json for hand labelling in
eval/corpus/labels/<name>.yaml:

    <fingerprint>: {label: tp | fp, actionable: true | false, note: "..."}

``label`` is factual (is the reported delta real?); ``actionable`` is whether a reviewer would be
expected to act (PLAN.md §1 "effective false positive"). Inline precision counts only
deterministic-tier findings, the ones posted as review comments.

    python eval/tools/replay_history.py full-stack-fastapi-template --commits 300
"""

from __future__ import annotations

import argparse
import json
import subprocess
import time
from pathlib import Path

import yaml
from authgraph.api import diff_trees
from authgraph.cache.summaries import MemoryCache
from authgraph.workspace.tree import GitTree

EVAL = Path(__file__).resolve().parents[1]


def git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args], check=True, capture_output=True, text=True
    ).stdout


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("name")
    ap.add_argument("--commits", type=int, default=200)
    args = ap.parse_args()
    repo = EVAL / "corpus" / "checkouts" / args.name
    if git(repo, "rev-parse", "--is-shallow-repository").strip() == "true":
        git(repo, "fetch", "-q", "--unshallow", "origin")
    shas = git(
        repo,
        "rev-list",
        "--first-parent",
        f"--max-count={args.commits}",
        "HEAD",
        "--",
        "*.py",
        ".accessguard.yml",
    ).split()
    cache = MemoryCache()
    out, timings = [], []
    for sha in reversed(shas):
        parents = git(repo, "rev-list", "--parents", "-n", "1", sha).split()[1:]
        if not parents:
            continue
        t0 = time.perf_counter()
        r = diff_trees(GitTree(repo, parents[0]), GitTree(repo, sha), args.name, cache)
        timings.append(time.perf_counter() - t0)
        subject = git(repo, "log", "-1", "--format=%s", sha).strip()
        for f in r.findings:
            out.append({"commit": sha, "subject": subject, **f.model_dump(mode="json")})
    labels_file = EVAL / "corpus" / "labels" / f"{args.name}.yaml"
    labels = yaml.safe_load(labels_file.read_text()) if labels_file.exists() else {}
    labels = labels or {}

    def lab(f: dict[str, object]) -> dict[str, object]:
        return labels.get(f["fingerprint"], {}) or {}

    tp = sum(1 for f in out if lab(f).get("label") == "tp")
    fp = sum(1 for f in out if lab(f).get("label") == "fp")
    inline = [f for f in out if f["tier"] == "deterministic" and lab(f)]
    acted = sum(1 for f in inline if lab(f).get("actionable"))
    report = {
        "repo": args.name,
        "commits": len(timings),
        "findings": len(out),
        "labelled_tp": tp,
        "labelled_fp": fp,
        "unlabelled": len(out) - tp - fp,
        "inline_labelled": len(inline),
        "inline_actionable": acted,
        "p95_seconds": sorted(timings)[int(len(timings) * 0.95)] if timings else 0,
        "items": out,
    }
    (EVAL / "reports").mkdir(exist_ok=True)
    (EVAL / "reports" / f"replay-{args.name}.json").write_text(json.dumps(report, indent=2))
    print(json.dumps({k: v for k, v in report.items() if k != "items"}))
    for f in out:
        tag = lab(f).get("label", "?")
        print(
            f"[{tag}] {f['fingerprint'][:12]} {f['commit'][:10]} {f['tier'][:5]} {f['rule_id']} "
            f"{f['title']}  ({f['subject'][:50]})"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
