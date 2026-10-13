from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_permission_diff_bot.cli import main
from agent_permission_diff_bot.engine import build_report
from agent_permission_diff_bot.sources import read_dir_snapshot


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


def test_missing_explicit_policy_exits_two_with_stderr(capsys, tmp_path: Path) -> None:
    base, head = tmp_path / "base", tmp_path / "head"
    base.mkdir()
    head.mkdir()
    code = main(
        [
            "diff",
            "--base-dir",
            str(base),
            "--head-dir",
            str(head),
            "--policy",
            str(tmp_path / "missing.yml"),
        ]
    )
    assert code == 2
    assert "policy file does not exist" in capsys.readouterr().err


def test_validate_json_malformed_payload_is_contract_error(tmp_path: Path, capsys) -> None:
    invalid = tmp_path / "invalid.json"
    invalid.write_text("{bad", encoding="utf-8")
    code = main(["simulate", "--validate-json", str(invalid)])
    assert code == 2
    assert json.loads(capsys.readouterr().out) == {
        "valid": False,
        "errors": ["Malformed JSON at line 1, column 2."],
    }


def test_missing_directory_root_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError, match="scan root does not exist"):
        read_dir_snapshot(tmp_path / "missing")


def test_missing_explicit_cli_root_exits_two_with_stderr(tmp_path: Path, capsys) -> None:
    head = tmp_path / "head"
    head.mkdir()
    code = main(
        [
            "diff",
            "--base-dir",
            str(tmp_path / "missing"),
            "--head-dir",
            str(head),
        ]
    )
    assert code == 2
    assert "scan root does not exist" in capsys.readouterr().err


def test_oversized_input_is_reported_as_incomplete(tmp_path: Path) -> None:
    (tmp_path / ".mcp.json").write_bytes(b" " * (2 * 1024 * 1024 + 1))
    label, files = read_dir_snapshot(tmp_path)
    report = build_report("base", {}, label, files)
    finding = next(item for item in report.findings if item.rule_id == "APD013")
    assert "exceeds 2 MiB" in finding.evidence[0]


def test_incomplete_base_scan_cannot_produce_clean_pass(tmp_path: Path) -> None:
    (tmp_path / ".mcp.json").write_bytes(b" " * (2 * 1024 * 1024 + 1))
    _, files = read_dir_snapshot(tmp_path)
    report = build_report("base", files, "head", {})
    assert any(finding.rule_id == "APD013" for finding in report.findings)


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


def test_observe_mode_records_gate_without_failing(tmp_path: Path) -> None:
    base = tmp_path / "base"
    head = tmp_path / "head"
    base.mkdir()
    head.mkdir()
    (head / ".mcp.json").write_text(
        '{"mcpServers":{"x":{"headers":{"Authorization":"${TOKEN}"},"tools":["*"]}}}',
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
            "--mode",
            "observe",
            "--fail-on",
            "high",
        ]
    )

    payload = json.loads(output.read_text(encoding="utf-8"))
    assert code == 0
    assert payload["gate"]["mode"] == "observe"
    assert payload["gate"]["status"] == "observe"
    assert payload["gate"]["threshold_met"] is True
    assert payload["gate"]["exit_code"] == 0


def test_enforce_mode_records_fail_gate_at_threshold(tmp_path: Path) -> None:
    base = tmp_path / "base"
    head = tmp_path / "head"
    base.mkdir()
    head.mkdir()
    (head / ".mcp.json").write_text(
        '{"mcpServers":{"x":{"headers":{"Authorization":"${TOKEN}"},"tools":["*"]}}}',
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
            "--mode",
            "enforce",
            "--fail-on",
            "high",
        ]
    )

    payload = json.loads(output.read_text(encoding="utf-8"))
    assert code == 2
    assert payload["gate"]["mode"] == "enforce"
    assert payload["gate"]["status"] == "fail"
    assert payload["gate"]["threshold_met"] is True
    assert payload["gate"]["exit_code"] == 2


def test_policy_acknowledgement_keeps_finding_visible_but_unblocks_gate(
    tmp_path: Path,
) -> None:
    base = tmp_path / "base"
    head = tmp_path / "head"
    base.mkdir()
    head.mkdir()
    (head / ".mcp.json").write_text(
        '{"mcpServers":{"x":{"headers":{"Authorization":"${TOKEN}"},"tools":["*"]}}}',
        encoding="utf-8",
    )
    policy = tmp_path / ".agent-permission-diff.yml"
    policy.write_text(
        """
acknowledgements:
  - rule_id: APD004
    paths:
      - .mcp.json
    reason: Broad tool access is intentionally limited to a local read-only test server.
    expires: "2999-12-31"
  - rule_id: APD101
    paths:
      - .mcp.json
    reason: Credential use is intentionally limited to a local read-only test server.
    expires: "2999-12-31"
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
            "--mode",
            "enforce",
            "--fail-on",
            "high",
            "--policy",
            str(policy),
        ]
    )

    payload = json.loads(output.read_text(encoding="utf-8"))
    finding = next(item for item in payload["findings"] if item["rule_id"] == "APD004")
    assert code == 0
    assert finding["acknowledged"] is True
    assert finding["acknowledgement"]["reason"].startswith("Broad tool access")
    assert payload["acknowledged_findings_count"] == 2
    assert payload["gate_findings_count"] == 0
    assert payload["gate"]["status"] == "pass"
    assert payload["gate"]["reason"] == "All findings were acknowledged by policy."


def test_expired_policy_acknowledgement_does_not_unblock_gate(tmp_path: Path) -> None:
    base = tmp_path / "base"
    head = tmp_path / "head"
    base.mkdir()
    head.mkdir()
    (head / ".mcp.json").write_text(
        '{"mcpServers":{"x":{"headers":{"Authorization":"${TOKEN}"},"tools":["*"]}}}',
        encoding="utf-8",
    )
    policy = tmp_path / ".agent-permission-diff.yml"
    policy.write_text(
        """
acknowledgements:
  - rule_id: APD004
    paths:
      - .mcp.json
    reason: This acknowledgement is intentionally expired for test coverage.
    expires: "2000-01-01"
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
            "--mode",
            "enforce",
            "--fail-on",
            "high",
            "--policy",
            str(policy),
        ]
    )

    payload = json.loads(output.read_text(encoding="utf-8"))
    finding = next(item for item in payload["findings"] if item["rule_id"] == "APD004")
    assert code == 2
    assert finding["acknowledged"] is False
    assert payload["acknowledged_findings_count"] == 0
    assert payload["gate_findings_count"] >= 1
