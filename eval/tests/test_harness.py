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


@pytest.mark.parametrize("usable", [False, True])
def test_route_recall_reports_skipped_repositories(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, usable: bool
) -> None:
    monkeypatch.setattr(harness, "EVAL_DIR", tmp_path)
    truth_dir = tmp_path / "truth"
    truth_dir.mkdir()
    route = {"method": "POST", "path": "/items", "kind": "APIRoute"}
    (truth_dir / "missing.json").write_text(json.dumps({"routes": [route]}))
    (truth_dir / "empty.json").write_text(json.dumps({"routes": [{**route, "kind": "Route"}]}))
    if usable:
        checkout = tmp_path / "corpus" / "checkouts" / "ready"
        checkout.mkdir(parents=True)
        (checkout / "main.py").write_text(
            'from fastapi import FastAPI\napp = FastAPI()\n@app.post("/items")\ndef items(): ...\n'
        )
        (truth_dir / "ready.json").write_text(json.dumps({"routes": [route]}))
    rr = harness.route_recall(truth_dir)
    assert rr["skipped"] == {"empty": "no APIRoute truth", "missing": "checkout missing"}
    assert rr["recall"] == (1.0 if usable else None)
    report = harness.evaluate([])
    report["route_recall"] = rr
    md = harness.to_markdown(report)
    assert "Skipped `empty`: no APIRoute truth" in md
    assert "Skipped `missing`: checkout missing" in md
    assert bool(harness.gate_failures(report, {"min_route_recall": 0.95})) is not usable


def test_routes_cli_gate_fails_without_truth(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    collect = harness.route_recall
    monkeypatch.setattr(harness, "route_recall", lambda: collect(tmp_path / "absent"))
    assert harness.main(["--routes", "--enforce-gates", "--out", str(tmp_path)]) == 1
    assert "GATE FAIL: route recall unavailable: no usable truth routes" in capsys.readouterr().out
    assert json.loads((tmp_path / "report.json").read_text())["route_recall"]["recall"] is None
