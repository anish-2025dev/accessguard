from pathlib import Path

from authgraph.cli import main


def test_diff_on_identical_trees_reports_nothing(tmp_path: Path, capsys) -> None:
    (tmp_path / "app.py").write_text("x = 1\n")
    assert main(["diff", str(tmp_path), str(tmp_path)]) == 0
    assert capsys.readouterr().out.strip() == "[]"
