"""Stack detection (FR-1.5): languages + tree + manifests, per directory (monorepo-aware)."""

from __future__ import annotations

import posixpath
from collections.abc import Iterable
from typing import Any

MANIFESTS = {
    "pyproject.toml": "python",
    "requirements.txt": "python",
    "setup.py": "python",
    "package.json": "node",
}
MARKERS = {
    "supabase/migrations": "supabase",
    "firestore.rules": "firebase",
    "storage.rules": "firebase",
    "database.rules.json": "firebase",
}


def detect(languages: dict[str, int], paths: Iterable[str]) -> dict[str, Any]:
    """Which analyzers apply where. Contents are not fetched here; frameworks are confirmed by
    the engine during the scan, so this only routes work and is shown to maintainers."""
    projects: dict[str, set[str]] = {}
    data_layers: set[str] = set()
    for p in paths:
        name = posixpath.basename(p)
        if name in MANIFESTS:
            projects.setdefault(posixpath.dirname(p) or ".", set()).add(MANIFESTS[name])
        for marker, layer in MARKERS.items():
            if (
                p.startswith(marker + "/")
                or p == marker
                or p.endswith("/" + marker)
                or ("/" + marker + "/" in "/" + p)
            ):
                data_layers.add(layer)
    return {
        "languages": sorted(languages, key=lambda k: -languages[k]),
        "projects": {d: sorted(v) for d, v in sorted(projects.items())},
        "data_layers": sorted(data_layers),
        "supported": "Python" in languages,  # Phase 1 engine: FastAPI
    }
