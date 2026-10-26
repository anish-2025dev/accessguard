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
label = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(label)


@pytest.fixture
def labels(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    (tmp_path / "reports").mkdir()
    (tmp_path / "reports" / "replay-example.json").write_text(
        json.dumps({"items": [{"fingerprint": "abcdef"}, {"fingerprint": "123456"}]})
    )
    directory = tmp_path / "corpus" / "labels"
    directory.mkdir(parents=True)
    path = directory / "example.yaml"
    path.write_text("# preserve this file if validation fails\n{}\n")
    monkeypatch.setattr(label, "EVAL", tmp_path)
    return path


@pytest.mark.parametrize("value", ["tp", "fp", "tp:", "fp:", "tp:act", "fp:act"])
def test_valid_labels(labels: Path, monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    monkeypatch.setattr(sys, "argv", ["label.py", "example", f"abc={value}", "note"])
    assert label.main() == 0
    assert yaml.safe_load(labels.read_text()) == {
        "abcdef": {
            "label": value.split(":")[0],
            "actionable": value.endswith(":act"),
            "note": "note",
        }
    }


@pytest.mark.parametrize(
    "value",
    [
        "",
        "true",
        "TP",
        "tp:no",
        "fp:act:act",
        "fp:active",
        "unknown",
        "tp:action",
        "fp:act:extra",
        ":act",
    ],
)
def test_invalid_label_rejects_entire_batch_before_write(
    labels: Path, monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    before = labels.read_bytes()
    monkeypatch.setattr(
        sys, "argv", ["label.py", "example", "123=tp:act", "valid", f"abc={value}", "invalid"]
    )
    with pytest.raises(SystemExit, match="expected"):
        label.main()
    assert labels.read_bytes() == before
