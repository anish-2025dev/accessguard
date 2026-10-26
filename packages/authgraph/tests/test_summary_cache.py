from pathlib import Path

import pytest
from authgraph.cache.summaries import DirCache, load
from authgraph.lang.python.summary import FileSummary


@pytest.mark.parametrize("raw", ["", '{"path":', "{}", "[]", '{"path": 12}'])
def test_invalid_cached_summary_is_a_miss(tmp_path: Path, raw: str) -> None:
    cache = DirCache(tmp_path)
    cache.set("summary", raw)
    assert load(DirCache(tmp_path), "summary") is None


def test_cache_round_trip_and_missing_entry(tmp_path: Path) -> None:
    cache = DirCache(tmp_path)
    assert load(cache, "missing") is None
    summary = FileSummary(path="a.py", module="a", blob_sha="blob")
    cache.set("summary", summary.model_dump_json())
    assert load(DirCache(tmp_path), "summary") == summary


def test_atomic_replace_failure_preserves_entry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cache = DirCache(tmp_path)
    cache.set("summary", "old")
    target = tmp_path / "summary.json"

    def fail_replace(source: Path, destination: Path) -> None:
        assert source.parent == target.parent and source != target
        assert source.read_text() == "new"
        assert destination == target and target.read_text() == "old"
        raise OSError("replace failed")

    monkeypatch.setattr("authgraph.cache.summaries.os.replace", fail_replace)
    with pytest.raises(OSError, match="replace failed"):
        cache.set("summary", "new")
    assert cache.get("summary") == DirCache(tmp_path).get("summary") == "old"
    assert list(tmp_path.iterdir()) == [target]
