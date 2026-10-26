"""``accessguard-sandbox supabase <dir|rev>``: catalog exposures as JSON (eval cross-checks)."""

from __future__ import annotations

import argparse
import json

from authgraph.workspace.tree import open_tree

from accessguard_sandbox.supabase import PostgresSandbox


def main() -> int:
    ap = argparse.ArgumentParser(prog="accessguard-sandbox")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sb = sub.add_parser("supabase", help="replay supabase/migrations in a network-less Postgres")
    sb.add_argument("source")
    sb.add_argument("--image")
    args = ap.parse_args()
    result = PostgresSandbox(args.image).replay(open_tree(args.source))
    print(
        json.dumps(
            {
                "files": result.files,
                "errors": result.errors,
                "exposures": [e.model_dump(mode="json") for e in result.exposures],
            },
            indent=2,
        )
    )
    return 1 if result.errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
