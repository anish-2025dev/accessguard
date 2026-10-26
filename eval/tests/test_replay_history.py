import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

_spec = importlib.util.spec_from_file_location(
    "ag_replay_history", Path(__file__).parents[1] / "tools" / "replay_history.py"
)
assert _spec and _spec.loader
replay = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(replay)


def git(repo: Path, *args: str) -> str:
    return replay.git(repo, *args).strip()


def commit(repo: Path, path: str, text: str) -> str:
    (repo / path).write_text(text)
    git(repo, "add", path)
    git(repo, "-c", "user.name=Test", "-c", "user.email=test@example.com", "commit", "-qm", path)
    return git(repo, "rev-parse", "HEAD")


@pytest.fixture
def shallow_checkout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, str, str]:
    origin = tmp_path / "origin"
    git(tmp_path, "init", "-q", str(origin))
    initial = "from fastapi import FastAPI\napp = FastAPI()\n"
    commit(origin, "main.py", initial)
    python_sha = commit(origin, "main.py", initial + "@app.post('/items')\ndef create(): ...\n")
    config_sha = commit(origin, ".accessguard.yml", "public_routes:\n  - route: 'POST /items'\n")
    # More non-Python commits than --commits: deepening by that count is insufficient.
    for i in range(6):
        commit(origin, "README.md", f"revision {i}\n")
    checkout = tmp_path / "corpus" / "checkouts" / "example"
    checkout.parent.mkdir(parents=True)
    git(tmp_path, "clone", "-q", "--depth=1", origin.as_uri(), str(checkout))
    assert git(checkout, "rev-parse", "--is-shallow-repository") == "true"
    monkeypatch.setattr(replay, "EVAL", tmp_path)
    monkeypatch.setattr(sys, "argv", ["replay_history.py", "example", "--commits", "2"])
    return checkout, python_sha, config_sha


def test_replay_unshallows_and_includes_configuration_changes(
    tmp_path: Path, shallow_checkout: tuple[Path, str, str]
) -> None:
    checkout, python_sha, config_sha = shallow_checkout
    assert replay.main() == 0
    assert git(checkout, "rev-parse", "--is-shallow-repository") == "false"
    report = json.loads((tmp_path / "reports" / "replay-example.json").read_text())
    assert report["commits"] == 2
    assert {(item["commit"], item["rule_id"]) for item in report["items"]} == {
        (python_sha, "AG-AUTH-001"),
        (config_sha, "AG-CFG-001"),
    }


def test_replay_preserves_commit_count_limit(
    tmp_path: Path, shallow_checkout: tuple[Path, str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(sys, "argv", ["replay_history.py", "example", "--commits", "1"])
    assert replay.main() == 0
    report = json.loads((tmp_path / "reports" / "replay-example.json").read_text())
    assert report["commits"] == 1
    assert {item["commit"] for item in report["items"]} == {shallow_checkout[2]}


def test_fetch_failure_propagates_without_report(
    tmp_path: Path, shallow_checkout: tuple[Path, str, str]
) -> None:
    checkout, _, _ = shallow_checkout
    git(checkout, "remote", "set-url", "origin", str(tmp_path / "missing-origin"))
    with pytest.raises(subprocess.CalledProcessError):
        replay.main()
    assert not (tmp_path / "reports" / "replay-example.json").exists()
