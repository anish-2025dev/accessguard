import os
from pathlib import Path

import pytest
from authgraph.cache.summaries import DirCache, MemoryCache, cache_key, load
from authgraph.engine import summarize_tree
from authgraph.facts.models import GuardKind, Verdict
from authgraph.guards.config import Config, GuardDecl
from authgraph.workspace.tree import DirectoryTree, blob_sha

from .helpers import endpoints, write_tree


@pytest.mark.parametrize("raw", ["{", "{}", '{"path": 42}', ""])
def test_invalid_cache_is_a_miss_and_is_rebuilt(tmp_path: Path, raw: str) -> None:
    source = b"x = 1\n"
    root = write_tree(tmp_path / "source", {"main.py": source.decode()})
    cache = DirCache(tmp_path / "cache")
    key = cache_key("python", blob_sha(source))
    cache.set(key, raw)
    assert load(DirCache(cache.root), key) is None
    result, coverage = summarize_tree(DirectoryTree(root), cache)
    assert coverage.cache_hits == 0 and coverage.files_parsed == 1
    assert load(DirCache(cache.root), key) == result["main.py"]


def test_missing_cache_entry_is_a_miss(tmp_path: Path) -> None:
    assert load(DirCache(tmp_path), "missing") is None
    assert load(MemoryCache(), "missing") is None


def test_cache_write_replaces_complete_entry_atomically(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cache = DirCache(tmp_path)
    cache.set("entry", "old")
    target = cache._file("entry")
    replace = os.replace

    def observe(source: Path, destination: Path) -> None:
        assert source.parent == destination.parent == tmp_path
        assert source != destination == target
        assert target.read_text() == "old"
        assert source.read_text() == "new"
        replace(source, destination)

    monkeypatch.setattr(os, "replace", observe)
    cache.set("entry", "new")
    assert cache.get("entry") == DirCache(tmp_path).get("entry") == "new"
    assert list(tmp_path.iterdir()) == [target]


def test_failed_cache_replace_preserves_old_entry_and_cleans_temp(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cache = DirCache(tmp_path)
    cache.set("entry", "old")

    def fail(*args: object) -> None:
        raise OSError("synthetic replace failure")

    monkeypatch.setattr(os, "replace", fail)
    with pytest.raises(OSError, match="synthetic replace failure"):
        cache.set("entry", "new")
    assert cache.get("entry") == DirCache(tmp_path).get("entry") == "old"
    assert list(tmp_path.iterdir()) == [cache._file("entry")]


def test_guard_declarations_require_exact_symbols() -> None:
    guard = GuardDecl(symbol="app.deps.check", kind=GuardKind.AUTHZ_ROLE)
    config = Config(auth_guards=[guard])
    assert config.guard_decl("app.deps.check") == guard
    for symbol in ("check", "deps.check", "other.app.deps.check", "other.check"):
        assert config.guard_decl(symbol) is None
    assert Config(auth_guards=[GuardDecl(symbol="check")]).guard_decl("app.deps.check") is None


def test_same_named_function_does_not_inherit_configured_guard(tmp_path: Path) -> None:
    result = endpoints(
        tmp_path,
        {
            "main.py": (
                "from fastapi import FastAPI, Depends\n"
                "from trusted import check as trusted_check\nfrom other import check\n"
                "app = FastAPI()\n"
                "@app.post('/trusted')\ndef trusted(user=Depends(trusted_check)): ...\n"
                "@app.post('/other')\ndef other(user=Depends(check)): ...\n"
            ),
            "trusted.py": "def check(): return 1\n",
            "other.py": "def check(): return 1\n",
            ".accessguard.yml": "auth_guards:\n  - symbol: trusted.check\n",
        },
    )
    assert result["POST /trusted"].authn == Verdict.AUTH
    assert result["POST /other"].authn == Verdict.NO_AUTH
