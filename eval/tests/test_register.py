"""Registration tests use synthetic secrets and never contact GitHub."""

import importlib.util
import io
import json
import os
import stat
from pathlib import Path
from unittest.mock import patch

import pytest

_spec = importlib.util.spec_from_file_location(
    "ag_register", Path(__file__).parents[2] / "deploy" / "github-app" / "register.py"
)
assert _spec and _spec.loader
register = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(register)


@pytest.mark.parametrize("exists", [False, True])
def test_secure_write_restricts_permissions_before_modifying_content(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, exists: bool
) -> None:
    path = tmp_path / "secret"
    previous = "old content longer than new content" if exists else ""
    if exists:
        path.write_text(previous)
        path.chmod(0o666)
    real_fdopen = os.fdopen

    def checked_fdopen(fd: int, *args, **kwargs):
        output = real_fdopen(fd, *args, **kwargs)
        assert path.read_text() == previous  # opening must not truncate a permissive file
        real_write, real_truncate = output.write, output.truncate

        def check_write(content: str) -> int:
            assert stat.S_IMODE(os.fstat(fd).st_mode) == 0o600
            return real_write(content)

        def check_truncate(size: int) -> int:
            assert stat.S_IMODE(os.fstat(fd).st_mode) == 0o600
            return real_truncate(size)

        monkeypatch.setattr(output, "write", check_write)
        monkeypatch.setattr(output, "truncate", check_truncate)
        return output

    monkeypatch.setattr(register.os, "fdopen", checked_fdopen)
    register.secure_write(path, "new content")
    assert path.read_text() == "new content"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_conversion_keeps_environment_secrets_separate(tmp_path: Path) -> None:
    for env in ("dev", "prod"):
        app = {
            "id": 1,
            "slug": f"synthetic-{env}",
            "client_id": "synthetic-client",
            "client_secret": "synthetic-secret",
            "webhook_secret": "synthetic-webhook",
            "pem": f"synthetic-{env}-pem",
        }
        with patch.object(register.urllib.request, "urlopen") as urlopen:
            urlopen.return_value = io.StringIO(json.dumps(app))
            register.convert("synthetic-code", tmp_path / f".env.{env}")

    for env in ("dev", "prod"):
        env_file = tmp_path / f".env.{env}"
        pem = tmp_path / f".env.{env}.pem"
        assert pem.read_text() == f"synthetic-{env}-pem"
        assert f"GITHUB_PRIVATE_KEY_PATH={pem}\n" in env_file.read_text()
        assert stat.S_IMODE(env_file.stat().st_mode) == 0o600
        assert stat.S_IMODE(pem.stat().st_mode) == 0o600
