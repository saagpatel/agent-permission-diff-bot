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
