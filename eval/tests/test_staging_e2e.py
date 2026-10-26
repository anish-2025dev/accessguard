"""Staging Git authentication never enters argv or propagated failures."""

import base64
import importlib.util
import subprocess
from pathlib import Path
from unittest.mock import Mock

import pytest

_spec = importlib.util.spec_from_file_location(
    "staging_e2e", Path(__file__).parents[2] / "deploy" / "e2e" / "staging_e2e.py"
)
assert _spec and _spec.loader
staging = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(staging)


def test_push_credentials_are_only_in_environment(tmp_path, monkeypatch) -> None:
    case = tmp_path / "case"
    for name in ("base", "head"):
        (case / name).mkdir(parents=True)
        (case / name / "app.py").write_text(name)
    work = tmp_path / "work"
    work.mkdir()
    run = Mock(return_value=subprocess.CompletedProcess([], 0, stdout="head-sha\n"))
    monkeypatch.setattr(staging.subprocess, "run", run)
    token = "synthetic-e2e-token"
    assert staging.push_case("owner/repo", token, case, work) == ("e2e/case/base", "head-sha")
    pushes = [c for c in run.call_args_list if c.args[0][1] == "push"]
    assert len(pushes) == 2
    for call in run.call_args_list:
        assert token not in repr(call.args[0])
    for call in pushes:
        assert "https://github.com/owner/repo.git" in call.args[0]
        env = call.kwargs["env"]
        auth = env["GIT_CONFIG_VALUE_0"].removeprefix("Authorization: Basic ")
        assert base64.b64decode(auth).decode() == f"x-access-token:{token}"


def test_failed_git_does_not_propagate_sensitive_output(tmp_path, monkeypatch) -> None:
    token = "synthetic-secret"
    monkeypatch.setattr(
        staging.subprocess,
        "run",
        Mock(return_value=subprocess.CompletedProcess([], 128, stdout=token, stderr=token)),
    )
    with pytest.raises(RuntimeError, match="git push failed") as raised:
        staging.git(tmp_path, "push", "https://github.com/owner/repo.git", token=token)
    assert token not in str(raised.value)
    assert raised.value.__context__ is None
