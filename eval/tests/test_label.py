import importlib.util
import json
import sys
from pathlib import Path

import pytest
import yaml

_spec = importlib.util.spec_from_file_location(
    "ag_label", Path(__file__).parents[1] / "tools" / "label.py"
)
assert _spec and _spec.loader
label_tool = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(label_tool)


@pytest.fixture
def labels_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr(label_tool, "EVAL", tmp_path)
    (tmp_path / "reports").mkdir()
    (tmp_path / "reports" / "replay-example.json").write_text(
        json.dumps({"items": [{"fingerprint": "abc123"}, {"fingerprint": "def456"}]})
    )
    directory = tmp_path / "corpus" / "labels"
    directory.mkdir(parents=True)
    path = directory / "example.yaml"
    path.write_text("# Keep existing labels\n{}\n")
    return path


@pytest.mark.parametrize("value", ["tp", "fp", "tp:", "fp:", "tp:act", "fp:act"])
def test_valid_labels(labels_file: Path, monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    monkeypatch.setattr(sys, "argv", ["label.py", "example", f"abc={value}", "reviewed"])
    assert label_tool.main() == 0
    assert yaml.safe_load(labels_file.read_text())["abc123"] == {
        "label": value[:2],
        "actionable": value.endswith(":act"),
        "note": "reviewed",
    }


@pytest.mark.parametrize("value", ["", "TP", "unknown", "tp:action", "fp:act:extra", ":act"])
def test_invalid_label_rejects_entire_batch_before_writing(
    labels_file: Path, monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    original = labels_file.read_bytes()
    monkeypatch.setattr(
        sys,
        "argv",
        ["label.py", "example", "abc=tp:act", "valid first entry", f"def={value}", "invalid"],
    )
    with pytest.raises(SystemExit, match="expected"):
        label_tool.main()
    assert labels_file.read_bytes() == original
