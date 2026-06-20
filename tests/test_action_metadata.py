from __future__ import annotations

from pathlib import Path

import yaml


def test_action_metadata_shape() -> None:
    action = yaml.safe_load(Path("action.yml").read_text(encoding="utf-8"))

    assert action["runs"]["using"] == "composite"
    assert action["inputs"]["mode"]["default"] == "observe"
    assert action["inputs"]["comment"]["default"] == "false"
    assert action["inputs"]["upload-sarif"]["default"] == "false"
    assert "json-file" in action["outputs"]
    assert "gate-status" in action["outputs"]
    assert "gate-threshold-met" in action["outputs"]


def test_action_preserves_scan_exit_code_after_outputs() -> None:
    text = Path("action.yml").read_text(encoding="utf-8")

    assert "code=$?" in text
    assert 'echo "exit-code=${code}"' in text
    assert 'exit "${code}"' in text


def test_action_supports_sticky_pull_request_comments() -> None:
    text = Path("action.yml").read_text(encoding="utf-8")

    assert "<!-- agent-permission-diff-bot -->" in text
    assert "COMMENT: ${{ inputs.comment }}" in text
    assert "repos/${GITHUB_REPOSITORY}/issues/${EVENT_PR_NUMBER}/comments" in text
    assert "comment_status=0" in text
    assert "pull-requests: write permissions" in text
