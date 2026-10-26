import importlib.util
import json
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


@pytest.mark.parametrize("mode", ["no_truth_files", "empty_truth", "missing_checkout"])
def test_routes_gate_fails_without_usable_truth(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], mode: str
) -> None:
    truth = tmp_path / "corpus" / "truth"
    truth.mkdir(parents=True)
    if mode != "no_truth_files":
        routes = (
            [] if mode == "empty_truth" else [{"method": "GET", "path": "/", "kind": "APIRoute"}]
        )
        (truth / "example.json").write_text(json.dumps({"routes": routes}))
    monkeypatch.setattr(harness, "EVAL_DIR", tmp_path)
    monkeypatch.setattr(harness, "load_cases", lambda: [])
    (tmp_path / "gates.yaml").write_text("min_route_recall: 0.95\n")
    # main's production default truth directory is bound at import time.
    collect = harness.route_recall
    monkeypatch.setattr(harness, "route_recall", lambda: collect(truth))
    assert harness.main(["--routes", "--enforce-gates", "--out", str(tmp_path / "out")]) == 1
    output = capsys.readouterr().out
    assert "GATE FAIL: route recall unavailable" in output
    if mode != "no_truth_files":
        assert "Skipped `example`" in output


def test_route_recall_keeps_usable_repositories_and_reports_skips(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    truth = tmp_path / "corpus" / "truth"
    truth.mkdir(parents=True)
    route = {"method": "GET", "path": "/items", "kind": "APIRoute"}
    for name in ("usable", "missing"):
        (truth / f"{name}.json").write_text(json.dumps({"routes": [route]}))
    checkout = tmp_path / "corpus" / "checkouts" / "usable"
    checkout.mkdir(parents=True)
    (checkout / "main.py").write_text(
        "from fastapi import FastAPI\napp = FastAPI()\n@app.get('/items')\ndef items(): ...\n"
    )
    monkeypatch.setattr(harness, "EVAL_DIR", tmp_path)
    report = harness.route_recall(truth)
    assert report["recall"] == 1
    assert report["repos"]["usable"]["found"] == 1
    assert report["skipped_repos"] == {"missing": "checkout missing"}
    assert (
        harness.gate_failures({"rules": {}, "pure_move_findings": 0, "route_recall": report}, {})
        == []
    )
