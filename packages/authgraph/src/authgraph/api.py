"""Stable entry points used by the CLI, the GitHub App and the eval harness."""

from __future__ import annotations

from pathlib import Path
from typing import Any


def diff_paths(base: Path, head: Path) -> list[dict[str, Any]]:
    """Analyze two checkouts and return findings introduced in ``head``.

    Phase 0 placeholder: the engine lands in Phase 1, so no findings are produced yet.
    """
    del base, head
    return []
