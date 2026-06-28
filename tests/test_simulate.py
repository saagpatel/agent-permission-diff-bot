from __future__ import annotations

import io
import json
import urllib.error
from pathlib import Path

from agent_permission_diff_bot.cli import main
from agent_permission_diff_bot.simulate import (
    GitHubActionsLiveProbeOptions,
    GitHubProbeError,
    build_simulation,
    fetch_github_actions_readonly_metadata,
    list_simulation_probes,
    list_simulation_scenarios,
    render_simulation_markdown,
    resolve_github_pull_head_sha,
)


def test_simulates_command_send_write_deploy_and_bypass() -> None:
    report = build_simulation(
        command="git commit --no-verify -m x && curl https://example.com && vercel deploy --prod"
    )

    assert report.capabilities["write"].level == "yes"
    assert report.capabilities["send"].level == "yes"
    assert report.capabilities["deploy"].level == "yes"
    assert report.capabilities["bypass"].level == "yes"
    assert report.safety_boundary.startswith("Static simulation only")


def test_simulates_workflow_oidc_deploy_without_live_probe() -> None:
    report = build_simulation(
        workflow_text="""
name: Publish
on:
  push:
permissions:
  id-token: write
  contents: read
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: pypa/gh-action-pypi-publish@release/v1
"""
    )

    assert report.capabilities["deploy"].level == "yes"
    assert report.capabilities["escalate"].level == "yes"
    assert any("OIDC provider trust policy" in gap for gap in report.live_probe_needed)


def test_simulates_mcp_config_and_supplied_mcpaudit_json() -> None:
    report = build_simulation(
        mcp_config_text="""
{"mcpServers":{"github":{"url":"https://api.githubcopilot.com/mcp","headers":{"Authorization":"${TOKEN}"},"tools":["*"]}}}
""",
        mcpaudit_json_text=json.dumps(
            {
                "audits": [
                    {
                        "server": {"name": "github"},
                        "permissions": [
                            {"category": "file_read"},
                            {"category": "file_write"},
                            {"category": "network"},
                            {"category": "shell_execution"},
                        ],
                    }
                ]
            }
        ),
    )

    assert report.capabilities["read"].level == "yes"
    assert report.capabilities["write"].level == "yes"
    assert report.capabilities["send"].level == "yes"
    assert report.capabilities["escalate"].level == "yes"
    assert any("Broad MCP tool allowlist" in gap for gap in report.live_probe_needed)


def test_simulates_subagent_permission_mode() -> None:
    report = build_simulation(
        subagent_text="""---
name: shipper
tools: Bash, mcp__github__create_pull_request
permissionMode: bypassPermissions
---
Ship the change.
"""
    )

    assert report.capabilities["write"].level == "possible"
    assert report.capabilities["send"].level == "possible"
    assert report.capabilities["bypass"].level == "yes"
    assert report.capabilities["escalate"].level == "possible"


def test_cli_simulate_writes_json_and_markdown(tmp_path: Path) -> None:
    workflow = tmp_path / "workflow.yml"
    workflow.write_text(
        """
name: Deploy
on:
  workflow_dispatch:
jobs:
  deploy:
    runs-on: [self-hosted, macOS]
    steps:
      - run: wrangler deploy
""",
        encoding="utf-8",
    )
    json_path = tmp_path / "simulation.json"
    markdown_path = tmp_path / "simulation.md"

    code = main(
        [
            "simulate",
            "--command",
            "gh pr create --repo saagpatel/demo",
            "--workflow",
            str(workflow),
            "--json",
            str(json_path),
            "--markdown",
            str(markdown_path),
        ]
    )

    payload = json.loads(json_path.read_text(encoding="utf-8"))
    markdown = markdown_path.read_text(encoding="utf-8")
    assert code == 0
    assert payload["mode"] == "static/no-credential/no-network"
    assert payload["capabilities"]["write"]["level"] == "yes"
    assert payload["capabilities"]["deploy"]["level"] == "yes"
    assert "Agent Permission Simulation" in markdown


def test_render_markdown_lists_live_probe_gaps() -> None:
    report = build_simulation(mcp_config_text='{"mcpServers":{"local":{"command":"npx"}}}')

    markdown = render_simulation_markdown(report)

    assert "## Live Probe Needed" in markdown
    assert "MCPAudit connected or supplied tool-schema evidence" in markdown


def test_lists_builtin_simulation_scenarios() -> None:
    names = {item["name"] for item in list_simulation_scenarios()}

    assert names == {
        "command-approval-laundering",
        "github-actions-oidc-deploy",
        "mcp-broad-tool-schema-drift",
        "claude-subagent-inherited-bypass",
        "hook-policy-bypass-gap",
    }


def test_scenario_command_approval_laundering() -> None:
    report = build_simulation(scenarios=("command-approval-laundering",))

    assert report.capabilities["write"].level == "yes"
    assert report.capabilities["send"].level == "yes"
    assert report.capabilities["deploy"].level == "yes"
    assert report.capabilities["bypass"].level == "yes"
    assert any(item.kind == "scenario" for item in report.inputs)
    assert any("approval laundering" in item for item in report.deterministic_evidence)


def test_scenario_github_actions_oidc_deploy() -> None:
    report = build_simulation(scenarios=("github-actions-oidc-deploy",))

    assert report.capabilities["deploy"].level == "yes"
    assert report.capabilities["send"].level == "possible"
    assert report.capabilities["escalate"].level == "yes"
    assert any("environment protection" in gap for gap in report.live_probe_needed)


def test_scenario_mcp_broad_tool_schema_drift() -> None:
    report = build_simulation(scenarios=("mcp-broad-tool-schema-drift",))

    assert report.capabilities["read"].level == "yes"
    assert report.capabilities["write"].level == "yes"
    assert report.capabilities["send"].level == "yes"
    assert report.capabilities["escalate"].level == "yes"
    assert report.capabilities["bypass"].level == "possible"
    assert any("input schemas" in gap for gap in report.live_probe_needed)


def test_scenario_claude_subagent_inherited_bypass() -> None:
    report = build_simulation(scenarios=("claude-subagent-inherited-bypass",))

    assert report.capabilities["write"].level == "possible"
    assert report.capabilities["send"].level == "possible"
    assert report.capabilities["bypass"].level == "yes"
    assert report.capabilities["escalate"].level == "possible"
    assert any("tool inheritance" in gap for gap in report.live_probe_needed)


def test_scenario_hook_policy_bypass_gap() -> None:
    report = build_simulation(scenarios=("hook-policy-bypass-gap",))

    assert report.capabilities["bypass"].level == "possible"
    assert any(
        "Hook snapshot includes PreToolUse" in item for item in report.deterministic_evidence
    )
    assert any("hook disable writability" in gap for gap in report.live_probe_needed)


def test_unknown_scenario_is_reported_as_static_gap() -> None:
    report = build_simulation(scenarios=("not-a-real-scenario",))

    assert report.inputs[0].kind == "scenario"
    assert report.inputs[0].status == "unknown"
    assert (
        "Unknown scenario fixture `not-a-real-scenario` was requested." in report.live_probe_needed
    )


def test_cli_simulate_lists_scenarios(capsys) -> None:
    code = main(["simulate", "--list-scenarios"])

    payload = json.loads(capsys.readouterr().out)
    names = {item["name"] for item in payload}
    assert code == 0
    assert "mcp-broad-tool-schema-drift" in names


def test_probes_are_off_by_default() -> None:
    report = build_simulation(command="git status")

    assert report.live_probe_evidence == []
    assert all(item.kind != "probe" for item in report.inputs)


def test_lists_supported_live_readonly_probes() -> None:
    names = {item["name"] for item in list_simulation_probes()}

    assert names == {"github-actions-readonly"}


def test_unknown_probe_is_reported_without_lookup() -> None:
    report = build_simulation(probes=("not-a-real-probe",))

    assert report.inputs[0].kind == "probe"
    assert report.inputs[0].status == "unknown"
    assert report.live_probe_evidence == []
    assert any("no live lookup was attempted" in gap for gap in report.live_probe_needed)


def test_github_actions_probe_requires_supplied_snapshot() -> None:
    report = build_simulation(probes=("github-actions-readonly",))

    assert report.inputs[0].kind == "probe"
    assert report.inputs[0].status == "missing_context"
    assert report.live_probe_evidence == []
    assert any("--github-actions-probe-json" in gap for gap in report.live_probe_needed)


def test_github_actions_probe_records_separate_live_evidence() -> None:
    report = build_simulation(
        command="git status",
        probes=("github-actions-readonly",),
        github_actions_probe_json_text=json.dumps(
            {
                "repository": "saagpatel/agent-permission-diff-bot",
                "pull_number": 12,
                "head_sha": "abc123",
                "check_runs": [
                    {
                        "name": "Package (3.13)",
                        "status": "completed",
                        "conclusion": "success",
                    }
                ],
                "workflow_runs": [
                    {
                        "name": "CI",
                        "status": "completed",
                        "conclusion": "success",
                    }
                ],
            }
        ),
    )

    assert any("Command has read-shaped verb" in item for item in report.deterministic_evidence)
    assert any("Package (3.13)" in item for item in report.live_probe_evidence)
    assert any("GitHub Actions workflow `CI`" in item for item in report.live_probe_evidence)
    assert all("Package (3.13)" not in item for item in report.deterministic_evidence)


def test_render_markdown_lists_live_probe_evidence() -> None:
    report = build_simulation(
        probes=("github-actions-readonly",),
        github_actions_probe_json_text=json.dumps(
            {"check_runs": [{"name": "Agent-facing permission diff", "conclusion": "success"}]}
        ),
    )

    markdown = render_simulation_markdown(report)

    assert "## Live Probe Evidence" in markdown
    assert "Agent-facing permission diff" in markdown


def test_cli_simulate_lists_probes(capsys) -> None:
    code = main(["simulate", "--list-probes"])

    payload = json.loads(capsys.readouterr().out)
    names = {item["name"] for item in payload}
    assert code == 0
    assert "github-actions-readonly" in names


def test_cli_simulate_accepts_github_actions_probe_snapshot(tmp_path: Path) -> None:
    snapshot = tmp_path / "checks.json"
    output = tmp_path / "simulation.json"
    snapshot.write_text(
        json.dumps({"check_runs": [{"name": "Package (3.11)", "conclusion": "success"}]}),
        encoding="utf-8",
    )

    code = main(
        [
            "simulate",
            "--probe",
            "github-actions-readonly",
            "--github-actions-probe-json",
            str(snapshot),
            "--json",
            str(output),
        ]
    )

    payload = json.loads(output.read_text(encoding="utf-8"))
    assert code == 0
    assert payload["deterministic_evidence"] == []
    assert any("Package (3.11)" in item for item in payload["live_probe_evidence"])


def test_github_actions_live_probe_requires_explicit_context() -> None:
    report = build_simulation(
        probes=("github-actions-readonly",),
        github_actions_live_options=GitHubActionsLiveProbeOptions(),
    )

    assert report.inputs[0].status == "live_requested"
    assert report.live_probe_evidence == []
    assert any("--github-repository" in gap for gap in report.live_probe_needed)
    assert any("--github-ref" in gap for gap in report.live_probe_needed)


def test_github_actions_live_probe_uses_injected_fetcher_without_token_leak() -> None:
    calls: list[GitHubActionsLiveProbeOptions] = []

    def fake_fetcher(options: GitHubActionsLiveProbeOptions) -> dict[str, object]:
        calls.append(options)
        return {
            "repository": options.repository,
            "head_sha": options.ref,
            "pull_number": options.pull_number,
            "check_runs": [{"name": "Package (3.13)", "conclusion": "success"}],
        }

    report = build_simulation(
        command="git status",
        probes=("github-actions-readonly",),
        github_actions_live_options=GitHubActionsLiveProbeOptions(
            repository="saagpatel/agent-permission-diff-bot",
            ref="abc123",
            pull_number=13,
            token_env="SECRET_GITHUB_TOKEN",
        ),
        github_actions_probe_fetcher=fake_fetcher,
    )

    assert len(calls) == 1
    assert calls[0].repository == "saagpatel/agent-permission-diff-bot"
    assert any("Command has read-shaped verb" in item for item in report.deterministic_evidence)
    assert any("api.github.com" in item for item in report.live_probe_evidence)
    assert any("env:SECRET_GITHUB_TOKEN" in item for item in report.live_probe_evidence)
    serialized = json.dumps(report.to_dict())
    assert "Package (3.13)" in serialized
    assert "SECRET_GITHUB_TOKEN" in serialized
    assert "ghp_" not in serialized


def test_github_actions_live_probe_blocks_unallowlisted_host() -> None:
    def fake_fetcher(_: GitHubActionsLiveProbeOptions) -> dict[str, object]:
        raise AssertionError("fetcher should not be called when validation fails")

    report = build_simulation(
        probes=("github-actions-readonly",),
        github_actions_live_options=GitHubActionsLiveProbeOptions(
            repository="saagpatel/agent-permission-diff-bot",
            ref="abc123",
            allowed_hosts=("example.com",),
        ),
        github_actions_probe_fetcher=fake_fetcher,
    )

    assert report.live_probe_evidence == []
    assert any("api.github.com is not allowlisted" in gap for gap in report.live_probe_needed)


def test_cli_github_actions_live_degrades_safely_without_context(capsys) -> None:
    code = main(["simulate", "--probe", "github-actions-readonly", "--github-actions-live"])

    output = capsys.readouterr().out
    assert code == 0
    assert "live_requested" in output
    assert "--github-repository" in output
    assert "--github-ref" in output


def test_github_pull_number_resolves_ref_with_injected_resolver() -> None:
    resolver_calls: list[GitHubActionsLiveProbeOptions] = []
    fetcher_calls: list[GitHubActionsLiveProbeOptions] = []

    def fake_resolver(options: GitHubActionsLiveProbeOptions) -> str:
        resolver_calls.append(options)
        return "resolved-sha"

    def fake_fetcher(options: GitHubActionsLiveProbeOptions) -> dict[str, object]:
        fetcher_calls.append(options)
        return {"check_runs": [{"name": "Package (3.12)", "conclusion": "success"}]}

    report = build_simulation(
        probes=("github-actions-readonly",),
        github_actions_live_options=GitHubActionsLiveProbeOptions(
            repository="saagpatel/agent-permission-diff-bot",
            pull_number=14,
        ),
        github_actions_probe_fetcher=fake_fetcher,
        github_pull_resolver=fake_resolver,
    )

    assert len(resolver_calls) == 1
    assert fetcher_calls[0].ref == "resolved-sha"
    assert any("resolved to head SHA `resolved-sha`" in item for item in report.live_probe_evidence)
    assert any("Package (3.12)" in item for item in report.live_probe_evidence)


def test_github_pull_number_resolution_failure_degrades_to_gap() -> None:
    def fake_resolver(_: GitHubActionsLiveProbeOptions) -> str:
        raise GitHubProbeError("pull resolution failed safely")

    report = build_simulation(
        probes=("github-actions-readonly",),
        github_actions_live_options=GitHubActionsLiveProbeOptions(
            repository="saagpatel/agent-permission-diff-bot",
            pull_number=14,
        ),
        github_pull_resolver=fake_resolver,
    )

    assert report.live_probe_evidence == []
    assert "pull resolution failed safely" in report.live_probe_needed
    assert any("--github-ref" in gap for gap in report.live_probe_needed)


def test_fetch_github_actions_metadata_uses_get_only_allowlisted_requests(monkeypatch) -> None:
    calls = []
    responses = [
        _FakeHTTPResponse({"check_runs": [{"name": "Package (3.11)", "conclusion": "success"}]}),
        _FakeHTTPResponse({"workflow_runs": [{"name": "CI", "conclusion": "success"}]}),
    ]

    def fake_urlopen(request, timeout):
        calls.append((request, timeout))
        return responses.pop(0)

    monkeypatch.setattr("agent_permission_diff_bot.simulate.urllib.request.urlopen", fake_urlopen)

    payload = fetch_github_actions_readonly_metadata(
        GitHubActionsLiveProbeOptions(
            repository="saagpatel/agent-permission-diff-bot",
            ref="abc123",
            timeout_seconds=2.5,
        )
    )

    assert [call[0].get_method() for call in calls] == ["GET", "GET"]
    assert all(call[0].full_url.startswith("https://api.github.com/") for call in calls)
    assert all(call[1] == 2.5 for call in calls)
    assert payload["check_runs"][0]["name"] == "Package (3.11)"
    assert payload["workflow_runs"][0]["name"] == "CI"


def test_resolve_github_pull_head_sha_uses_get_only_allowlisted_request(monkeypatch) -> None:
    calls = []

    def fake_urlopen(request, timeout):
        calls.append((request, timeout))
        return _FakeHTTPResponse({"head": {"sha": "resolved-sha"}})

    monkeypatch.setattr("agent_permission_diff_bot.simulate.urllib.request.urlopen", fake_urlopen)

    sha = resolve_github_pull_head_sha(
        GitHubActionsLiveProbeOptions(
            repository="saagpatel/agent-permission-diff-bot",
            pull_number=15,
            timeout_seconds=3.0,
        )
    )

    assert sha == "resolved-sha"
    assert len(calls) == 1
    assert calls[0][0].get_method() == "GET"
    assert calls[0][0].full_url == (
        "https://api.github.com/repos/saagpatel/agent-permission-diff-bot/pulls/15"
    )
    assert calls[0][1] == 3.0


def test_fetch_github_actions_metadata_reports_rate_limit_without_mutation(monkeypatch) -> None:
    def fake_urlopen(_request, timeout=None):
        assert timeout == 10.0
        raise urllib.error.HTTPError(
            url="https://api.github.com/repos/owner/repo/commits/ref/check-runs",
            code=403,
            msg="rate limited",
            hdrs={"x-ratelimit-remaining": "0"},
            fp=io.BytesIO(b""),
        )

    monkeypatch.setattr("agent_permission_diff_bot.simulate.urllib.request.urlopen", fake_urlopen)

    try:
        fetch_github_actions_readonly_metadata(
            GitHubActionsLiveProbeOptions(repository="owner/repo", ref="abc123")
        )
    except GitHubProbeError as exc:
        assert "rate-limited" in str(exc)
        assert "no mutation was attempted" in str(exc)
    else:
        raise AssertionError("expected GitHubProbeError")


def test_fetch_github_actions_metadata_reports_malformed_json_without_mutation(monkeypatch) -> None:
    def fake_urlopen(_request, timeout=None):
        assert timeout == 10.0
        return _FakeRawHTTPResponse(b"not-json")

    monkeypatch.setattr("agent_permission_diff_bot.simulate.urllib.request.urlopen", fake_urlopen)

    try:
        fetch_github_actions_readonly_metadata(
            GitHubActionsLiveProbeOptions(repository="owner/repo", ref="abc123")
        )
    except GitHubProbeError as exc:
        assert "no mutation was attempted" in str(exc)
    else:
        raise AssertionError("expected GitHubProbeError")


class _FakeHTTPResponse:
    def __init__(self, payload: dict[str, object]) -> None:
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, _exc_type, _exc, _traceback) -> None:
        return None

    def read(self) -> bytes:
        return json.dumps(self.payload).encode("utf-8")


class _FakeRawHTTPResponse:
    def __init__(self, payload: bytes) -> None:
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, _exc_type, _exc, _traceback) -> None:
        return None

    def read(self) -> bytes:
        return self.payload
