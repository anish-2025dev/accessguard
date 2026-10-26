"""Summary cache keyed by git blob SHA (FR-3.6; PLAN.md §6.9 ``sum:{lang}:{blob}:{engine}``).

Summaries hold facts, never source text, so they are safe to keep (30-day TTL in Redis for the
App). The CLI uses an in-process dict, optionally backed by a directory (``AUTHGRAPH_CACHE_DIR``).
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Protocol

from pydantic import ValidationError

from authgraph import ENGINE_VERSION
from authgraph.lang.python.summary import FileSummary


def cache_key(lang: str, blob_sha: str) -> str:
    return f"sum:{lang}:{blob_sha}:{ENGINE_VERSION}"


class SummaryCache(Protocol):
    def get(self, key: str) -> str | None: ...
    def set(self, key: str, value: str) -> None: ...


class MemoryCache:
    def __init__(self) -> None:
        self._d: dict[str, str] = {}

    def get(self, key: str) -> str | None:
        return self._d.get(key)

    def set(self, key: str, value: str) -> None:
        self._d[key] = value


class DirCache(MemoryCache):
    def __init__(self, root: Path) -> None:
        super().__init__()
        self.root = root
        root.mkdir(parents=True, exist_ok=True)

    def _file(self, key: str) -> Path:
        return self.root / (key.replace(":", "_") + ".json")

    def get(self, key: str) -> str | None:
        v = super().get(key)
        if v is None and self._file(key).exists():
            v = self._file(key).read_text(encoding="utf-8")
            super().set(key, v)
        return v

    def set(self, key: str, value: str) -> None:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=self.root, delete=False
        ) as f:
            temp = Path(f.name)
            try:
                f.write(value)
                f.close()
                os.replace(temp, self._file(key))
            finally:
                temp.unlink(missing_ok=True)
        super().set(key, value)


def default_cache() -> SummaryCache:
    d = os.environ.get("AUTHGRAPH_CACHE_DIR")
    return DirCache(Path(d)) if d else MemoryCache()


def load(cache: SummaryCache, key: str) -> FileSummary | None:
    raw = cache.get(key)
    try:
        return FileSummary.model_validate_json(raw) if raw else None
    except ValidationError:
        return None
