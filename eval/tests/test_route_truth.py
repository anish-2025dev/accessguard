"""Route collection orchestration tests never run Docker or import corpus code."""

import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from unittest.mock import Mock

import pytest

_spec = importlib.util.spec_from_file_location(
    "ag_route_truth", Path(__file__).parents[1] / "tools" / "route_truth.py"
)
assert _spec and _spec.loader
route_truth = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(route_truth)


@pytest.fixture
def collection(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Mock:
    monkeypatch.setattr(route_truth, "CHECKOUTS", tmp_path)
    (tmp_path / "example").mkdir()
    run = Mock(return_value=subprocess.CompletedProcess([], 0, '{"app": "main.py:app"}'))
    monkeypatch.setattr(route_truth.subprocess, "run", run)
    return run


def test_build_and_dump_have_separate_timeouts(collection: Mock) -> None:
    data = route_truth.truth_for({"name": "example", "ref": "synthetic-ref"})
    build, dump = collection.call_args_list
    assert build.kwargs["timeout"] == route_truth.BUILD_TIMEOUT
    assert dump.kwargs["timeout"] == route_truth.RUN_TIMEOUT
    assert build.kwargs["timeout"] > dump.kwargs["timeout"] > 0
    assert data["app"] == "main.py:app"


@pytest.mark.parametrize("stage", [0, 1])
def test_timeout_propagates_as_a_repository_failure(collection: Mock, stage: int) -> None:
    results = [subprocess.CompletedProcess([], 0), subprocess.CompletedProcess([], 0)]
    results[stage] = subprocess.TimeoutExpired("docker", 1)
    collection.side_effect = results
    with pytest.raises(subprocess.TimeoutExpired):
        route_truth.truth_for({"name": "example", "ref": "synthetic-ref"})


def test_missing_application_reports_import_errors(collection: Mock) -> None:
    collection.return_value.stdout = json.dumps(
        {"app": None, "routes": [], "errors": ["synthetic import failure"]}
    )
    with pytest.raises(ValueError, match=r"no application selected.*synthetic import failure"):
        route_truth.truth_for({"name": "example", "ref": "synthetic-ref"})


def test_invalid_json_shape_is_a_repository_failure(collection: Mock) -> None:
    collection.return_value.stdout = "[]"
    with pytest.raises(ValueError, match="did not return a JSON object"):
        route_truth.truth_for({"name": "example", "ref": "synthetic-ref"})


@pytest.mark.parametrize(
    "failure",
    [
        subprocess.CalledProcessError(1, "docker"),
        subprocess.TimeoutExpired("docker", 1),
        json.JSONDecodeError("invalid output", "", 0),
        ValueError("no application selected; errors: synthetic import failure"),
        OSError("docker unavailable"),
        None,
    ],
)
def test_main_records_failure_and_continues(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    failure: Exception | None,
) -> None:
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    (corpus / "repos.yaml").write_text("route_ground_truth:\n  - name: first\n  - name: second\n")
    monkeypatch.setattr(route_truth, "EVAL", tmp_path)
    truth = tmp_path / "truth"
    monkeypatch.setattr(route_truth, "TRUTH", truth)
    monkeypatch.setattr(sys, "argv", ["route_truth.py"])
    success = {"app": "main.py:app", "routes": [{"method": "GET", "path": "/"}]}
    collect = Mock(side_effect=[failure or success, success])
    monkeypatch.setattr(route_truth, "truth_for", collect)

    assert route_truth.main() == (1 if failure else 0)
    assert collect.call_count == 2
    assert (truth / "first.json").exists() == (failure is None)
    assert json.loads((truth / "second.json").read_text()) == success
    if failure:
        assert "first: FAILED" in capsys.readouterr().out
