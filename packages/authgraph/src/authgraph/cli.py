"""``authgraph`` command line interface (PLAN.md §2: ``authgraph scan``, ``authgraph diff``).

authgraph scan PATH [--format json|sarif|text]
authgraph diff BASE HEAD            # two directories
authgraph diff main..feature        # two git revisions of the repo in the current directory
authgraph diff BASE HEAD --fail-on high
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

from authgraph import __version__
from authgraph.api import SEVERITY_ORDER, diff_trees, scan
from authgraph.facts.models import Finding
from authgraph.output.sarif import to_sarif
from authgraph.workspace.tree import GitTree, SourceTree, open_tree


def _trees(base: str, head: str | None, repo: Path) -> tuple[SourceTree, SourceTree]:
    if head is None:
        if ".." not in base:
            raise SystemExit("diff needs BASE HEAD, or a git range BASE..HEAD")
        b, h = base.split("..", 1)
        return GitTree(repo, b), GitTree(repo, h or "HEAD")
    return open_tree(base), open_tree(head)


def _text(findings: list[Finding]) -> str:
    if not findings:
        return "No access-control regressions found.\n"
    lines = []
    for f in findings:
        lines.append(f"[{f.severity.upper()}] {f.rule_id} {f.title}")
        lines.append(f"    at {f.loc.path}:{f.loc.line}")
        lines += [f"    - {s.message}" for s in f.evidence]
    return "\n".join(lines) + "\n"


def _emit(findings: list[Finding], fmt: str, out: Any) -> None:
    if fmt == "sarif":
        json.dump(to_sarif(findings), out, indent=2)
        out.write("\n")
    elif fmt == "text":
        out.write(_text(findings))
    else:
        json.dump([f.model_dump(mode="json") for f in findings], out, indent=2)
        out.write("\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="authgraph", description=__doc__.split("\n\n")[0])
    parser.add_argument("--version", action="version", version=f"authgraph {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="list endpoints, their guards and verdicts")
    s.add_argument("path", type=Path)
    s.add_argument("--format", choices=["json", "text"], default="text")

    d = sub.add_parser("diff", help="report access-control regressions from base to head")
    d.add_argument("base")
    d.add_argument("head", nargs="?")
    d.add_argument("--repo", type=Path, default=Path("."), help="git repo for BASE..HEAD")
    d.add_argument("--repo-id", default="", help="repository id mixed into fingerprints")
    d.add_argument("--format", choices=["json", "sarif", "text"], default="json")
    d.add_argument("--output", "-o", type=Path)
    d.add_argument(
        "--fail-on", choices=["critical", "high", "medium", "low", "never"], default="never"
    )
    args = parser.parse_args(argv)

    if args.command == "scan":
        a = scan(open_tree(args.path))
        if args.format == "json":
            sys.stdout.write(a.facts.model_dump_json(indent=2) + "\n")
        else:
            for e in a.facts.endpoints:
                guards = ", ".join(f"{g.symbol.rsplit('.', 1)[-1]}:{g.kind}" for g in e.guards)
                sys.stdout.write(f"{e.authn.value:8} {e.id}  [{guards}]\n")
            c = Counter(e.authn.value for e in a.facts.endpoints)
            sys.stdout.write(f"\n{len(a.facts.endpoints)} endpoints: {dict(c)}\n")
        return 0

    base_tree, head_tree = _trees(args.base, args.head, args.repo)
    result = diff_trees(base_tree, head_tree, repo_id=args.repo_id)
    for err in result.config_errors:
        sys.stderr.write(f"warning: .accessguard.yml: {err}\n")
    if args.output:
        with args.output.open("w", encoding="utf-8") as fh:
            _emit(result.findings, args.format, fh)
    else:
        _emit(result.findings, args.format, sys.stdout)
    if args.fail_on != "never":
        limit = SEVERITY_ORDER[args.fail_on]
        if any(SEVERITY_ORDER[f.severity] <= limit for f in result.findings):
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
