import json
import subprocess
from pathlib import Path

import jsonschema
import pytest
from authgraph.cli import main

from .helpers import DEPS, write_tree

SCHEMA = json.loads((Path(__file__).parent / "data" / "sarif-schema-2.1.0.json").read_text())
MAIN = """
from fastapi import FastAPI, Depends
from deps import require_admin
app = FastAPI()
@app.delete("/admin/users/{uid}")
def delete_user(uid: int, admin=Depends(require_admin)): ...
"""


def test_diff_on_identical_trees_reports_nothing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / "app.py").write_text("x = 1\n")
    assert main(["diff", str(tmp_path), str(tmp_path)]) == 0
    assert capsys.readouterr().out.strip() == "[]"


def test_diff_git_range_sarif_validates_and_fail_on(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    write_tree(tmp_path, {"deps.py": DEPS, "main.py": MAIN})

    def git(*a: str) -> None:
        subprocess.run(
            ["git", "-C", str(tmp_path), "-c", "user.email=t@t", "-c", "user.name=t", *a],
            check=True,
            capture_output=True,
        )

    git("init", "-q", "-b", "main")
    git("add", ".")
    git("commit", "-qm", "base")
    (tmp_path / "main.py").write_text(MAIN.replace("admin=Depends(require_admin)", ""))
    git("commit", "-qam", "drop guard")

    rc = main(
        ["diff", "HEAD~1..HEAD", "--repo", str(tmp_path), "--format", "sarif", "--fail-on", "high"]
    )
    sarif = json.loads(capsys.readouterr().out)
    jsonschema.validate(sarif, SCHEMA)
    (result,) = sarif["runs"][0]["results"]
    assert rc == 1 and result["ruleId"] == "AG-AUTH-002"
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "main.py"


def test_scan_text(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    write_tree(tmp_path, {"deps.py": DEPS, "main.py": MAIN})
    assert main(["scan", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "auth     DELETE /admin/users/{uid}" in out and "1 endpoints" in out


def test_diff_bad_path_errors_cleanly(tmp_path: Path) -> None:
    """A nonexistent base/head is a clean CLI error, not a raw git traceback."""
    with pytest.raises(SystemExit) as ei:
        main(["diff", str(tmp_path / "nope-base"), str(tmp_path / "nope-head")])
    assert "cannot read" in str(ei.value)


def test_scan_bad_path_errors_cleanly(tmp_path: Path) -> None:
    with pytest.raises(SystemExit) as ei:
        main(["scan", str(tmp_path / "does-not-exist")])
    assert "cannot read" in str(ei.value)
