from __future__ import annotations

import json
from pathlib import Path

from agent_permission_diff_bot.cli import main


def test_directory_diff_writes_json_and_observe_exits_zero(tmp_path: Path) -> None:
    base = tmp_path / "base"
    head = tmp_path / "head"
    base.mkdir()
    head.mkdir()
    workflow_dir = head / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    (workflow_dir / "ci.yml").write_text(
        """
name: CI
on:
  pull_request:
jobs:
  test:
    runs-on: [self-hosted, macOS]
    steps:
      - run: echo hi
""",
        encoding="utf-8",
    )
    output = tmp_path / "report.json"

    code = main(
        [
            "diff",
            "--base-dir",
            str(base),
            "--head-dir",
            str(head),
            "--json",
            str(output),
        ]
    )

    assert code == 0
    assert '"APD001"' in output.read_text(encoding="utf-8")


def test_directory_diff_writes_sarif_and_step_summary(tmp_path: Path) -> None:
    base = tmp_path / "base"
    head = tmp_path / "head"
    base.mkdir()
    head.mkdir()
    (head / ".mcp.json").write_text(
        '{"mcpServers":{"x":{"headers":{"Authorization":"${TOKEN}"},"tools":["*"]}}}',
        encoding="utf-8",
    )
    sarif = tmp_path / "report.sarif"
    summary = tmp_path / "summary.md"

    code = main(
        [
            "diff",
            "--base-dir",
            str(base),
            "--head-dir",
            str(head),
            "--sarif",
            str(sarif),
            "--step-summary",
            "--step-summary-path",
            str(summary),
        ]
    )

    payload = json.loads(sarif.read_text(encoding="utf-8"))
    rule_ids = {result["ruleId"] for run in payload["runs"] for result in run["results"]}
    assert code == 0
    assert payload["version"] == "2.1.0"
    assert "APD004" in rule_ids
    assert "Agent Permission Diff" in summary.read_text(encoding="utf-8")


def test_warn_mode_exits_two_at_threshold(tmp_path: Path) -> None:
    base = tmp_path / "base"
    head = tmp_path / "head"
    base.mkdir()
    head.mkdir()
    (head / ".mcp.json").write_text(
        '{"mcpServers":{"x":{"headers":{"Authorization":"${TOKEN}"},"tools":["*"]}}}',
        encoding="utf-8",
    )

    code = main(
        [
            "diff",
            "--base-dir",
            str(base),
            "--head-dir",
            str(head),
            "--mode",
            "warn",
            "--fail-on",
            "high",
        ]
    )

    assert code == 2
