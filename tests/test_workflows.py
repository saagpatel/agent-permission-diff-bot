from __future__ import annotations

from pathlib import Path


def test_ci_workflow_runs_package_validation_matrix() -> None:
    text = Path(".github/workflows/ci.yml").read_text(encoding="utf-8")

    assert "pull_request:" in text
    assert "push:" in text
    assert "workflow_dispatch:" in text
    assert "Package (${{ matrix.python-version }})" in text
    assert '"3.11"' in text
    assert '"3.12"' in text
    assert '"3.13"' in text
    assert "uv run --python" in text
    assert "ruff format --check ." in text
    assert "ruff check ." in text
    assert "pytest" in text
    assert "uv build" in text


def test_acknowledgement_dogfood_workflow_exercises_enforce_policy() -> None:
    text = Path(".github/workflows/acknowledgement-dogfood.yml").read_text(encoding="utf-8")

    assert "workflow_dispatch:" in text
    assert "pull_request:" in text
    assert "uses: ./" in text
    assert "mode: enforce" in text
    assert "fail-on: high" in text
    assert "policy: .agent-permission-diff.yml" in text
    assert "Enforce mode without acknowledgements" in text
    assert "rule_id: APD004" in text
    assert "rule_id: APD101" in text
    assert 'steps.acknowledged.outputs.gate-status }}" = "pass"' in text
    assert 'test "${code}" = "2"' in text
    assert 'payload["acknowledged_findings_count"] == 2' in text
    assert 'payload["gate_findings_count"] == 0' in text
    assert 'payload["gate"]["status"] == "fail"' in text


def test_agent_permission_diff_workflow_comments_in_observe_mode() -> None:
    text = Path(".github/workflows/agent-permission-diff.yml").read_text(encoding="utf-8")

    assert "pull_request:" in text
    assert "issues: write" in text
    assert "pull-requests: write" in text
    assert "fetch-depth: 0" in text
    assert "uses: saagpatel/agent-permission-diff-bot@v0.4.0" in text
    assert "mode: observe" in text
    assert "fail-on: critical" in text
    assert 'comment: "true"' in text
    assert 'upload-sarif: "false"' in text
