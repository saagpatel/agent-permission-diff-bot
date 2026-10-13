from __future__ import annotations

import re
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
    assert '"3.14"' in text
    assert "paths:" not in text
    assert "astral-sh/setup-uv@1c37ad07a6a961277cf70c0d37d6f313000f5884" in text
    assert 'version: "0.13.0"' in text
    assert "run: make check" in text
    assert "run: make build" in text
    assert "UV_PYTHON: ${{ matrix.python-version }}" in text


def test_all_external_action_references_are_full_sha_pinned() -> None:
    paths = [
        *Path(".github/workflows").glob("*.yml"),
        Path("action.yml"),
        Path("docs/simulation-ci-recipe.md"),
        Path("docs/server-card-ci-recipe.md"),
        Path("README.md"),
    ]
    uses = re.compile(r"uses:\s*([^\s]+)")
    for path in paths:
        for reference in uses.findall(path.read_text(encoding="utf-8")):
            if reference.startswith("./"):
                continue
            owner, _, revision = reference.partition("@")
            assert owner and re.fullmatch(r"[0-9a-f]{40}", revision), (path, reference)


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
    assert "uses: ./" in text
    assert "mode: observe" in text
    assert "fail-on: critical" in text
    assert 'comment: "true"' in text
    assert 'upload-sarif: "false"' in text
