from __future__ import annotations

import json
from pathlib import Path

from agent_permission_diff_bot.cli import main
from agent_permission_diff_bot.simulate import build_simulation, render_simulation_markdown


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
