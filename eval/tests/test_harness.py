import importlib.util
import sys
from pathlib import Path

import pytest

_spec = importlib.util.spec_from_file_location(
    "ag_eval_harness", Path(__file__).parents[1] / "harness.py"
)
assert _spec and _spec.loader
harness = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = harness  # dataclasses resolve types via sys.modules
_spec.loader.exec_module(harness)


def test_all_cases_load_with_valid_kind() -> None:
    cases = harness.load_cases()
    assert len(cases) >= 10
    assert {c.kind for c in cases} <= {"positive", "negative", "move"}
    for c in cases:
        assert (c.root / "base").is_dir() and (c.root / "head").is_dir(), c.id
        assert (c.kind == "positive") == bool(c.expected), c.id


def test_metrics(monkeypatch: pytest.MonkeyPatch) -> None:
    case = harness.Case("c", "positive", Path("."), [("R1", "GET /a"), ("R1", "GET /b")])
    monkeypatch.setattr(
        harness,
        "diff_paths",
        lambda b, h: [
            {"rule_id": "R1", "endpoint_id": "GET /a"},
            {"rule_id": "R1", "endpoint_id": "GET /c"},
        ],
    )
    r = harness.evaluate([case])["rules"]["R1"]
    assert (r["tp"], r["fp"], r["fn"]) == (1, 1, 1)
    assert r["precision"] == 0.5 and r["recall"] == 0.5


def test_regression_detected() -> None:
    base = {"rules": {"R1": {"precision": 1.0, "recall": 1.0}}, "pure_move_findings": 0}
    cur = {"rules": {"R1": {"precision": 0.9, "recall": 1.0}}, "pure_move_findings": 0}
    assert harness.regressions(cur, base) == ["R1 precision: 100% -> 90%"]
    assert harness.regressions(base, base) == []
