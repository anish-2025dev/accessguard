"""``authgraph`` command line interface."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from authgraph import __version__
from authgraph.api import diff_paths


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="authgraph")
    parser.add_argument("--version", action="version", version=f"authgraph {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    d = sub.add_parser("diff", help="report access-control regressions from base to head")
    d.add_argument("base", type=Path)
    d.add_argument("head", type=Path)
    args = parser.parse_args(argv)

    if args.command == "diff":
        json.dump(diff_paths(args.base, args.head), sys.stdout, indent=2)
        sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
