"""``accessguard-sandbox supabase <dir|rev>``: catalog exposures as JSON (eval cross-checks)."""

from __future__ import annotations

import argparse
import json
import subprocess

from authgraph.workspace.tree import open_tree

from accessguard_sandbox.supabase import PostgresSandbox


def main() -> int:
    ap = argparse.ArgumentParser(prog="accessguard-sandbox")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sb = sub.add_parser("supabase", help="replay supabase/migrations in a network-less Postgres")
    sb.add_argument("source")
    sb.add_argument("--image")
    sb.add_argument("--probe", action="store_true", help="SET ROLE probes (FR-3.8b)")
    args = ap.parse_args()
    try:
        tree = open_tree(args.source)
    except subprocess.CalledProcessError as e:
        raise SystemExit(
            f"error: cannot read '{args.source}': not a directory, and not a git revision in the "
            f"current repository (git exited {e.returncode})"
        ) from e
    result = PostgresSandbox(args.image).replay(tree, probe=args.probe)
    print(
        json.dumps(
            {
                "files": result.files,
                "errors": result.errors,
                "exposures": [
                    {**e.model_dump(mode="json"), "proven": sorted(result.proven(e))}
                    for e in result.exposures
                ],
                "probes": [vars(p) for p in result.probes],
            },
            indent=2,
        )
    )
    return 1 if result.errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
