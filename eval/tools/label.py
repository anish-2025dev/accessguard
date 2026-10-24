"""Append hand labels for a replay report.

python eval/tools/label.py <repo> <fingerprint-prefix>=<tp|fp>[:act] "note" ...
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import yaml

EVAL = Path(__file__).resolve().parents[1]


def main() -> int:
    repo, *specs = sys.argv[1:]
    report = json.loads((EVAL / "reports" / f"replay-{repo}.json").read_text())
    path = EVAL / "corpus" / "labels" / f"{repo}.yaml"
    labels = (yaml.safe_load(path.read_text()) if path.exists() else None) or {}
    for spec, note in zip(specs[::2], specs[1::2], strict=True):
        prefix, _, value = spec.partition("=")
        label, _, act = value.partition(":")
        if label not in {"tp", "fp"} or act not in {"", "act"}:
            raise SystemExit(f"{spec}: expected <prefix>=<tp|fp>[:act]")
        matches = {f["fingerprint"] for f in report["items"] if f["fingerprint"].startswith(prefix)}
        if len(matches) != 1:
            raise SystemExit(f"{prefix}: {len(matches)} matches")
        labels[matches.pop()] = {"label": label, "actionable": act == "act", "note": note}
    path.write_text(
        "# Hand labels for eval/tools/replay_history.py (see its docstring).\n"
        + yaml.safe_dump(labels, sort_keys=True, allow_unicode=True, width=100)
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
