from __future__ import annotations

from pathlib import Path

import yaml


def test_action_metadata_shape() -> None:
    action = yaml.safe_load(Path("action.yml").read_text(encoding="utf-8"))

    assert action["runs"]["using"] == "composite"
    assert action["inputs"]["mode"]["default"] == "observe"
    assert action["inputs"]["upload-sarif"]["default"] == "false"
    assert "json-file" in action["outputs"]


def test_action_preserves_scan_exit_code_after_outputs() -> None:
    text = Path("action.yml").read_text(encoding="utf-8")

    assert "code=$?" in text
    assert 'echo "exit-code=${code}"' in text
    assert 'exit "${code}"' in text
