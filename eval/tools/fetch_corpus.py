"""Clone every corpus repo at its pinned ref into eval/corpus/checkouts/<name> (shallow)."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import yaml

EVAL = Path(__file__).resolve().parents[1]


def fetch(name: str, url: str, ref: str, dest_root: Path) -> Path:
    dest = dest_root / name
    if not (dest / ".git").exists():
        dest.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "init", "-q", str(dest)], check=True)
        subprocess.run(["git", "-C", str(dest), "remote", "add", "origin", url], check=True)
    subprocess.run(
        ["git", "-C", str(dest), "fetch", "-q", "--depth", "1", "origin", ref], check=True
    )
    subprocess.run(["git", "-C", str(dest), "checkout", "-q", "--force", "FETCH_HEAD"], check=True)
    return dest


def main() -> int:
    spec = yaml.safe_load((EVAL / "corpus" / "repos.yaml").read_text(encoding="utf-8"))
    only = set(sys.argv[1:])
    for group in spec.values():
        for repo in group:
            if only and repo["name"] not in only:
                continue
            print(f"fetching {repo['name']} @ {repo['ref'][:12]}")
            fetch(repo["name"], repo["url"], repo["ref"], EVAL / "corpus" / "checkouts")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
