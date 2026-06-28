from __future__ import annotations

import json
import os
import re
import shlex
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

import yaml

from agent_permission_diff_bot.surfaces import extract_atoms

CapabilityName = Literal["read", "write", "send", "deploy", "bypass", "escalate"]
CapabilityLevel = Literal["yes", "possible", "unknown", "no"]
InputKind = Literal[
    "command",
    "workflow",
    "mcp_config",
    "mcpaudit_json",
    "subagent",
    "hook_policy",
    "scenario",
    "probe",
]

CAPABILITIES: tuple[CapabilityName, ...] = (
    "read",
    "write",
    "send",
    "deploy",
    "bypass",
    "escalate",
)

READ_COMMAND_RE = re.compile(
    r"(^|[;&|]\s*)(cat|bat|less|more|head|tail|nl|sed|awk|grep|rg|find|ls|"
    r"git\s+(show|diff|log|status)|gh\s+(repo\s+view|pr\s+view|api\s+-X\s+GET))\b",
    re.IGNORECASE,
)
WRITE_COMMAND_RE = re.compile(
    r"(^|[;&|]\s*)(cp|mv|rm|mkdir|touch|chmod|chown|install|tee|"
    r"git\s+(add|commit|merge|rebase|cherry-pick|rm|mv|push)|"
    r"gh\s+(pr\s+(create|edit|merge|comment)|issue\s+(create|edit|comment|close)|"
    r"repo\s+(create|delete|fork)|release\s+(create|upload|delete))|"
    r"npm\s+(publish|deprecate)|pnpm\s+publish|yarn\s+npm\s+publish|"
    r"uv\s+(publish|add|remove|sync|lock)|pip\s+install)\b|"
    r"\b(sed\s+-i|perl\s+-pi)\b|(?<!\d)(^|[^<])>>?\s*(?!&|/dev/null\b)\S+",
    re.IGNORECASE,
)
SEND_COMMAND_RE = re.compile(
    r"(^|[;&|]\s*)(curl|wget|scp|rsync|ssh|nc|ncat|ftp|sftp)\b|"
    r"\bgh\s+(api|pr\s+comment|issue\s+comment|release\s+upload)\b|"
    r"https?://",
    re.IGNORECASE,
)
DEPLOY_COMMAND_RE = re.compile(
    r"\b(vercel\s+(deploy|--prod)|wrangler\s+(deploy|publish)|"
    r"firebase\s+deploy|netlify\s+deploy|render\s+deploy|fly\s+deploy|"
    r"docker\s+(push|buildx\s+build)|npm\s+publish|twine\s+upload|"
    r"pypi|gh\s+release\s+create)\b",
    re.IGNORECASE,
)
BYPASS_COMMAND_RE = re.compile(
    r"--no-verify|CODEX_HOOKS_DISABLE|disabled\.json|--dangerously-skip-permissions|"
    r"--skip-permissions|bypassPermissions|ignore-approval|skip[-_ ]?approval",
    re.IGNORECASE,
)
ESCALATE_COMMAND_RE = re.compile(
    r"(^|[;&|]\s*)(sudo|su)\b|chmod\s+[-+]?R?\s*777|chown\s+-R|"
    r"\bid-token:\s*write\b|--privileged|docker\s+run\b.*--privileged",
    re.IGNORECASE | re.DOTALL,
)

SUBAGENT_TOOL_MAP: tuple[tuple[str, tuple[CapabilityName, ...]], ...] = (
    ("Bash", ("read", "write", "send", "deploy", "escalate")),
    ("Task", ("bypass", "escalate")),
    ("Write", ("write",)),
    ("Edit", ("write",)),
    ("MultiEdit", ("write",)),
    ("NotebookEdit", ("write",)),
    ("Read", ("read",)),
    ("Grep", ("read",)),
    ("Glob", ("read",)),
    ("LS", ("read",)),
    ("WebFetch", ("read", "send")),
    ("WebSearch", ("read", "send")),
)

ScenarioName = Literal[
    "command-approval-laundering",
    "github-actions-oidc-deploy",
    "mcp-broad-tool-schema-drift",
    "claude-subagent-inherited-bypass",
    "hook-policy-bypass-gap",
]

SUPPORTED_PROBES: dict[str, dict[str, str]] = {
    "github-actions-readonly": {
        "name": "github-actions-readonly",
        "title": "GitHub Actions Read-Only Metadata",
        "description": (
            "Consumes a supplied GitHub Actions metadata snapshot and records check/run "
            "status as live-probe evidence. Optional live fetching requires an explicit "
            "repo/ref, api.github.com allowlist, and opt-in flag."
        ),
    },
}

GITHUB_API_HOST = "api.github.com"
GITHUB_REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
DEFAULT_GITHUB_TIMEOUT_SECONDS = 10.0
MAX_GITHUB_TIMEOUT_SECONDS = 30.0


@dataclass(frozen=True)
class GitHubActionsLiveProbeOptions:
    repository: str | None = None
    ref: str | None = None
    pull_number: int | None = None
    token_env: str | None = None
    timeout_seconds: float = DEFAULT_GITHUB_TIMEOUT_SECONDS
    allowed_hosts: tuple[str, ...] = (GITHUB_API_HOST,)

    def token_source(self) -> str:
        return f"env:{self.token_env}" if self.token_env else "unauthenticated"


@dataclass(frozen=True)
class GitHubPullResolution:
    head_sha: str
    head_repository: str | None = None
    base_repository: str | None = None

    @property
    def is_cross_repository(self) -> bool:
        return bool(
            self.head_repository
            and self.base_repository
            and self.head_repository != self.base_repository
        )


GitHubActionsProbeFetcher = Callable[[GitHubActionsLiveProbeOptions], dict[str, Any]]
GitHubPullResolver = Callable[[GitHubActionsLiveProbeOptions], GitHubPullResolution]


class GitHubProbeError(RuntimeError):
    pass


@dataclass(frozen=True)
class ScenarioFixture:
    name: ScenarioName
    title: str
    description: str
    command: str | None = None
    workflow_text: str | None = None
    mcp_config_text: str | None = None
    mcpaudit_json_text: str | None = None
    subagent_text: str | None = None
    hook_policy_text: str | None = None
    deterministic_evidence: tuple[str, ...] = ()
    live_probe_needed: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, str]:
        return {
            "name": self.name,
            "title": self.title,
            "description": self.description,
        }


SCENARIO_FIXTURES: dict[str, ScenarioFixture] = {
    "command-approval-laundering": ScenarioFixture(
        name="command-approval-laundering",
        title="Command Approval Laundering",
        description=(
            "A proposed command chains a benign-looking review action into a hook bypass, "
            "write, network send, and deploy-shaped operation."
        ),
        command=(
            "git diff -- . && git commit --no-verify -m ship && "
            "curl https://deploy.example.invalid/hook && vercel deploy --prod"
        ),
        deterministic_evidence=(
            "Scenario fixture models approval laundering through command chaining.",
        ),
    ),
    "github-actions-oidc-deploy": ScenarioFixture(
        name="github-actions-oidc-deploy",
        title="GitHub Actions OIDC Deploy Escalation",
        description=(
            "A workflow grants id-token write and runs a publish action, requiring static "
            "escalation/deploy detection plus live trust-policy review."
        ),
        workflow_text="""
name: Publish
on:
  workflow_dispatch:
permissions:
  contents: read
  id-token: write
jobs:
  publish:
    environment: production
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - uses: pypa/gh-action-pypi-publish@release/v1
""",
        live_probe_needed=(
            "Confirm cloud provider audience, subject, and environment protection rules.",
        ),
    ),
    "mcp-broad-tool-schema-drift": ScenarioFixture(
        name="mcp-broad-tool-schema-drift",
        title="MCP Broad Tool Allowlist And Schema Drift",
        description=(
            "An MCP config allows every remote tool while supplied audit evidence shows "
            "read, write, network, and shell execution categories."
        ),
        mcp_config_text=json.dumps(
            {
                "mcpServers": {
                    "github": {
                        "url": "https://api.githubcopilot.com/mcp",
                        "headers": {"Authorization": "${TOKEN}"},
                        "tools": ["*"],
                    }
                }
            }
        ),
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
                        "findings": [{"rule_id": "MCP018"}],
                    }
                ]
            }
        ),
        live_probe_needed=(
            "Compare current tools/list and input schemas against the supplied MCPAudit JSON.",
        ),
    ),
    "claude-subagent-inherited-bypass": ScenarioFixture(
        name="claude-subagent-inherited-bypass",
        title="Claude Subagent Inherited Or Bypass Permissions",
        description=(
            "A Claude subagent can inherit tools or explicitly bypass permissions, changing "
            "effective autonomy even when the parent task looks scoped."
        ),
        subagent_text="""---
name: release-runner
description: Ship the package when asked.
tools: Bash, Task, mcp__github__create_pull_request
permissionMode: bypassPermissions
---
Ship the release.
""",
        live_probe_needed=(
            "Confirm runtime subagent tool inheritance and parent-session permission mode.",
        ),
    ),
    "hook-policy-bypass-gap": ScenarioFixture(
        name="hook-policy-bypass-gap",
        title="Hook Policy Bypass Or Missing Deny Controls",
        description=(
            "A hook snapshot references disable controls and lacks explicit deny decision "
            "evidence, leaving bypass posture ambiguous."
        ),
        hook_policy_text=json.dumps(
            {
                "hooks": {
                    "PreToolUse": [{"matcher": "Bash", "command": "python guard.py"}],
                    "disabled.json": True,
                },
                "allow_hosts": ["api.github.com"],
            },
            indent=2,
        ),
        live_probe_needed=(
            "Confirm runtime hook installation, hook disable writability, and deny behavior.",
        ),
    ),
}


@dataclass
class CapabilityAssessment:
    capability: CapabilityName
    level: CapabilityLevel = "no"
    confidence: str = "high"
    evidence: list[str] = field(default_factory=list)

    def add(self, level: CapabilityLevel, confidence: str, evidence: str) -> None:
        self.level = _stronger_level(self.level, level)
        self.confidence = _weaker_confidence(self.confidence, confidence)
        if evidence and evidence not in self.evidence:
            self.evidence.append(evidence)

    def to_dict(self) -> dict[str, Any]:
        return {
            "level": self.level,
            "confidence": self.confidence,
            "evidence": self.evidence,
        }


@dataclass(frozen=True)
class SimulationInput:
    kind: InputKind
    source: str
    status: str = "parsed"
    notes: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "source": self.source,
            "status": self.status,
            "notes": list(self.notes),
        }


@dataclass
class SimulationReport:
    schema_version: str
    mode: str
    safety_boundary: str
    inputs: list[SimulationInput]
    capabilities: dict[CapabilityName, CapabilityAssessment]
    deterministic_evidence: list[str]
    live_probe_evidence: list[str]
    live_probe_needed: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "mode": self.mode,
            "safety_boundary": self.safety_boundary,
            "inputs": [item.to_dict() for item in self.inputs],
            "capabilities": {name: self.capabilities[name].to_dict() for name in CAPABILITIES},
            "deterministic_evidence": self.deterministic_evidence,
            "live_probe_evidence": self.live_probe_evidence,
            "live_probe_needed": self.live_probe_needed,
        }


class SimulationBuilder:
    def __init__(self) -> None:
        self.inputs: list[SimulationInput] = []
        self.capabilities = {name: CapabilityAssessment(capability=name) for name in CAPABILITIES}
        self.deterministic_evidence: list[str] = []
        self.live_probe_evidence: list[str] = []
        self.live_probe_needed: list[str] = []

    def add_input(
        self,
        kind: InputKind,
        source: str,
        *,
        status: str = "parsed",
        notes: tuple[str, ...] = (),
    ) -> None:
        self.inputs.append(SimulationInput(kind=kind, source=source, status=status, notes=notes))

    def add_capability(
        self,
        capability: CapabilityName,
        level: CapabilityLevel,
        confidence: str,
        evidence: str,
    ) -> None:
        self.capabilities[capability].add(level, confidence, evidence)
        self.add_evidence(evidence)

    def add_evidence(self, evidence: str) -> None:
        if evidence and evidence not in self.deterministic_evidence:
            self.deterministic_evidence.append(evidence)

    def add_live_probe_evidence(self, evidence: str) -> None:
        if evidence and evidence not in self.live_probe_evidence:
            self.live_probe_evidence.append(evidence)

    def add_gap(self, gap: str) -> None:
        if gap and gap not in self.live_probe_needed:
            self.live_probe_needed.append(gap)

    def build(self) -> SimulationReport:
        return SimulationReport(
            schema_version="agent-permission-simulation.v1",
            mode="static/no-credential/no-network",
            safety_boundary=(
                "Static simulation only: no credentials read, no network calls, no MCP server "
                "launches, no workflow dispatches, no deploys, and no destructive probes."
            ),
            inputs=self.inputs,
            capabilities=self.capabilities,
            deterministic_evidence=self.deterministic_evidence,
            live_probe_evidence=self.live_probe_evidence,
            live_probe_needed=self.live_probe_needed,
        )


def build_simulation(
    *,
    command: str | None = None,
    workflow_text: str | None = None,
    mcp_config_text: str | None = None,
    mcpaudit_json_text: str | None = None,
    subagent_text: str | None = None,
    hook_policy_text: str | None = None,
    scenarios: tuple[str, ...] = (),
    probes: tuple[str, ...] = (),
    github_actions_probe_json_text: str | None = None,
    github_actions_live_options: GitHubActionsLiveProbeOptions | None = None,
    github_actions_probe_fetcher: GitHubActionsProbeFetcher | None = None,
    github_pull_resolver: GitHubPullResolver | None = None,
) -> SimulationReport:
    builder = SimulationBuilder()
    for scenario in scenarios:
        _analyze_scenario(builder, scenario)
    if command:
        _analyze_command(builder, command)
    if workflow_text:
        _analyze_workflow(builder, workflow_text)
    if mcp_config_text:
        _analyze_mcp_config(builder, mcp_config_text)
    if mcpaudit_json_text:
        _analyze_mcpaudit_json(builder, mcpaudit_json_text)
    if subagent_text:
        _analyze_subagent(builder, subagent_text)
    if hook_policy_text:
        _analyze_hook_policy(builder, hook_policy_text)
    for probe in probes:
        _analyze_probe(
            builder,
            probe,
            github_actions_probe_json_text=github_actions_probe_json_text,
            github_actions_live_options=github_actions_live_options,
            github_actions_probe_fetcher=github_actions_probe_fetcher,
            github_pull_resolver=github_pull_resolver,
        )
    if not builder.inputs:
        builder.add_gap("No simulation inputs were supplied.")
    if not any(assessment.level != "no" for assessment in builder.capabilities.values()):
        builder.add_gap("Static inputs did not expose a concrete capability expansion.")
    return builder.build()


def list_simulation_scenarios() -> list[dict[str, str]]:
    return [fixture.to_dict() for fixture in SCENARIO_FIXTURES.values()]


def list_simulation_probes() -> list[dict[str, str]]:
    return list(SUPPORTED_PROBES.values())


def write_simulation_json(report: SimulationReport, path: Path) -> None:
    path.write_text(json.dumps(report.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_simulation_markdown(report: SimulationReport, path: Path) -> None:
    path.write_text(render_simulation_markdown(report), encoding="utf-8")


def render_simulation_markdown(report: SimulationReport) -> str:
    lines = [
        "# Agent Permission Simulation",
        "",
        f"- Mode: `{report.mode}`",
        f"- Safety boundary: {report.safety_boundary}",
        f"- Inputs: `{len(report.inputs)}`",
        "",
        "## Capability Summary",
        "",
        "| Capability | Level | Confidence | Evidence |",
        "|---|---|---|---|",
    ]
    for name in CAPABILITIES:
        assessment = report.capabilities[name]
        evidence = "; ".join(assessment.evidence[:3]) if assessment.evidence else ""
        lines.append(
            f"| `{name}` | `{assessment.level}` | `{assessment.confidence}` | {evidence} |"
        )

    lines.extend(["", "## Inputs", ""])
    for item in report.inputs:
        notes = f" ({'; '.join(item.notes)})" if item.notes else ""
        lines.append(f"- `{item.kind}` from `{item.source}`: `{item.status}`{notes}")

    lines.extend(["", "## Deterministic Evidence", ""])
    if report.deterministic_evidence:
        lines.extend(f"- {item}" for item in report.deterministic_evidence)
    else:
        lines.append("- None.")

    lines.extend(["", "## Live Probe Evidence", ""])
    if report.live_probe_evidence:
        lines.extend(f"- {item}" for item in report.live_probe_evidence)
    else:
        lines.append("- None.")

    lines.extend(["", "## Live Probe Needed", ""])
    if report.live_probe_needed:
        lines.extend(f"- {item}" for item in report.live_probe_needed)
    else:
        lines.append("- None for the supplied static evidence.")

    lines.append("")
    return "\n".join(lines)


def _analyze_scenario(builder: SimulationBuilder, name: str) -> None:
    fixture = SCENARIO_FIXTURES.get(name)
    if fixture is None:
        builder.add_input(
            "scenario",
            name,
            status="unknown",
            notes=("Scenario fixture was not recognized.",),
        )
        builder.add_gap(f"Unknown scenario fixture `{name}` was requested.")
        return

    builder.add_input("scenario", fixture.name, notes=(fixture.title,))
    builder.add_evidence(f"Scenario `{fixture.name}`: {fixture.description}")
    for evidence in fixture.deterministic_evidence:
        builder.add_evidence(evidence)
    for gap in fixture.live_probe_needed:
        builder.add_gap(gap)

    if fixture.command:
        _analyze_command(builder, fixture.command)
    if fixture.workflow_text:
        _analyze_workflow(builder, fixture.workflow_text)
    if fixture.mcp_config_text:
        _analyze_mcp_config(builder, fixture.mcp_config_text)
    if fixture.mcpaudit_json_text:
        _analyze_mcpaudit_json(builder, fixture.mcpaudit_json_text)
    if fixture.subagent_text:
        _analyze_subagent(builder, fixture.subagent_text)
    if fixture.hook_policy_text:
        _analyze_hook_policy(builder, fixture.hook_policy_text)


def _analyze_probe(
    builder: SimulationBuilder,
    name: str,
    *,
    github_actions_probe_json_text: str | None,
    github_actions_live_options: GitHubActionsLiveProbeOptions | None,
    github_actions_probe_fetcher: GitHubActionsProbeFetcher | None,
    github_pull_resolver: GitHubPullResolver | None,
) -> None:
    if name not in SUPPORTED_PROBES:
        builder.add_input(
            "probe",
            name,
            status="unknown",
            notes=("Probe was not recognized; no live lookup was attempted.",),
        )
        builder.add_gap(f"Unknown probe `{name}` was requested; no live lookup was attempted.")
        return

    if name == "github-actions-readonly":
        _analyze_github_actions_readonly_probe(
            builder,
            github_actions_probe_json_text,
            live_options=github_actions_live_options,
            fetcher=github_actions_probe_fetcher,
            pull_resolver=github_pull_resolver,
        )


def _analyze_github_actions_readonly_probe(
    builder: SimulationBuilder,
    text: str | None,
    *,
    live_options: GitHubActionsLiveProbeOptions | None,
    fetcher: GitHubActionsProbeFetcher | None,
    pull_resolver: GitHubPullResolver | None,
) -> None:
    if live_options is not None:
        _analyze_github_actions_live_probe(builder, live_options, fetcher, pull_resolver)
        return
    if not text:
        builder.add_input(
            "probe",
            "github-actions-readonly",
            status="missing_context",
            notes=("Requires supplied GitHub Actions metadata JSON.",),
        )
        builder.add_gap(
            "Probe `github-actions-readonly` requires a supplied GitHub Actions metadata "
            "snapshot via --github-actions-probe-json; no GitHub API call was made."
        )
        return

    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        builder.add_input("probe", "github-actions-readonly", status="parse_error")
        builder.add_gap("GitHub Actions read-only probe JSON could not be parsed.")
        return

    builder.add_input("probe", "github-actions-readonly", status="parsed")
    context = _github_probe_context(payload)
    builder.add_live_probe_evidence(
        f"GitHub Actions read-only metadata snapshot supplied{context}."
    )
    check_runs = _github_check_runs(payload)
    workflow_runs = _github_workflow_runs(payload)
    if not check_runs and not workflow_runs:
        builder.add_gap(
            "GitHub Actions metadata snapshot did not include check_runs or workflow_runs."
        )
        return

    for run in check_runs[:8]:
        builder.add_live_probe_evidence(_format_github_run("check", run))
    for run in workflow_runs[:8]:
        builder.add_live_probe_evidence(_format_github_run("workflow", run))


def _analyze_github_actions_live_probe(
    builder: SimulationBuilder,
    options: GitHubActionsLiveProbeOptions,
    fetcher: GitHubActionsProbeFetcher | None,
    pull_resolver: GitHubPullResolver | None,
) -> None:
    builder.add_input(
        "probe",
        "github-actions-readonly",
        status="live_requested",
        notes=(
            f"host={GITHUB_API_HOST}",
            f"token_source={options.token_source()}",
        ),
    )
    resolved_options = options
    if not options.ref and options.pull_number is not None:
        resolved_options = _resolve_github_pull_options(builder, options, pull_resolver)

    validation_errors = _github_live_probe_validation_errors(resolved_options)
    if validation_errors:
        for error in validation_errors:
            builder.add_gap(error)
        return

    fetch = fetcher or fetch_github_actions_readonly_metadata
    try:
        payload = fetch(resolved_options)
    except GitHubProbeError as exc:
        builder.add_gap(str(exc))
        return

    builder.add_live_probe_evidence(
        "GitHub Actions read-only metadata fetched from api.github.com "
        f"for repository `{resolved_options.repository}` ref `{resolved_options.ref}` "
        f"using token source `{resolved_options.token_source()}`."
    )
    _record_github_actions_probe_payload(builder, payload)


def _resolve_github_pull_options(
    builder: SimulationBuilder,
    options: GitHubActionsLiveProbeOptions,
    pull_resolver: GitHubPullResolver | None,
) -> GitHubActionsLiveProbeOptions:
    resolver_errors = _github_pull_resolver_validation_errors(options)
    if resolver_errors:
        for error in resolver_errors:
            builder.add_gap(error)
        return options
    resolve = pull_resolver or resolve_github_pull_head_sha
    try:
        resolution = resolve(options)
    except GitHubProbeError as exc:
        builder.add_gap(str(exc))
        return options
    builder.add_live_probe_evidence(
        f"GitHub pull request `#{options.pull_number}` resolved to head SHA "
        f"`{resolution.head_sha}` "
        "via api.github.com."
    )
    _record_github_pull_trust_evidence(builder, options, resolution)
    return GitHubActionsLiveProbeOptions(
        repository=options.repository,
        ref=resolution.head_sha,
        pull_number=options.pull_number,
        token_env=options.token_env,
        timeout_seconds=options.timeout_seconds,
        allowed_hosts=options.allowed_hosts,
    )


def _record_github_pull_trust_evidence(
    builder: SimulationBuilder,
    options: GitHubActionsLiveProbeOptions,
    resolution: GitHubPullResolution,
) -> None:
    if resolution.base_repository:
        builder.add_live_probe_evidence(
            f"GitHub pull request `#{options.pull_number}` base repository "
            f"`{resolution.base_repository}`."
        )
    if resolution.head_repository:
        builder.add_live_probe_evidence(
            f"GitHub pull request `#{options.pull_number}` head repository "
            f"`{resolution.head_repository}`."
        )
    if resolution.is_cross_repository:
        builder.add_live_probe_evidence(
            f"GitHub pull request `#{options.pull_number}` is cross-repository; "
            "fork/base trust differs from same-repository branches."
        )
        builder.add_gap(
            "Cross-repository pull request trust requires workflow trigger, fork approval, "
            "secret exposure, and pull_request_target review."
        )


def _record_github_actions_probe_payload(
    builder: SimulationBuilder,
    payload: object,
) -> None:
    context = _github_probe_context(payload)
    if context:
        builder.add_live_probe_evidence(f"GitHub Actions metadata context{context}.")
    check_runs = _github_check_runs(payload)
    workflow_runs = _github_workflow_runs(payload)
    if not check_runs and not workflow_runs:
        builder.add_gap("GitHub Actions metadata did not include check_runs or workflow_runs.")
        return
    for run in check_runs[:8]:
        builder.add_live_probe_evidence(_format_github_run("check", run))
    for run in workflow_runs[:8]:
        builder.add_live_probe_evidence(_format_github_run("workflow", run))


def _analyze_command(builder: SimulationBuilder, command: str) -> None:
    builder.add_input("command", "inline")
    compact = _compact(command)
    if READ_COMMAND_RE.search(command):
        builder.add_capability("read", "yes", "high", f"Command has read-shaped verb: `{compact}`")
    if WRITE_COMMAND_RE.search(command):
        builder.add_capability(
            "write", "yes", "high", f"Command has write-shaped verb: `{compact}`"
        )
    if SEND_COMMAND_RE.search(command):
        builder.add_capability(
            "send", "yes", "high", f"Command has network/send-shaped verb: `{compact}`"
        )
    if DEPLOY_COMMAND_RE.search(command):
        builder.add_capability(
            "deploy", "yes", "high", f"Command has deploy/publish-shaped verb: `{compact}`"
        )
    if BYPASS_COMMAND_RE.search(command):
        builder.add_capability(
            "bypass", "yes", "high", f"Command mentions approval/hook bypass: `{compact}`"
        )
    if ESCALATE_COMMAND_RE.search(command):
        builder.add_capability(
            "escalate", "yes", "high", f"Command has escalation-shaped token: `{compact}`"
        )
    if _command_has_unresolved_destination(command):
        builder.add_gap(
            "Command uses a runtime-expanded destination; static host/owner proof is incomplete."
        )


def _analyze_workflow(builder: SimulationBuilder, text: str) -> None:
    builder.add_input("workflow", "snapshot")
    atoms = extract_atoms(".github/workflows/simulated.yml", text)
    if not atoms:
        builder.add_gap("Workflow text could not be parsed into permission atoms.")
        return
    for atom in atoms:
        evidence = atom.evidence or f"{atom.action}: {atom.value}"
        if atom.action == "token_permission" and atom.verb in {"write", "write-all"}:
            builder.add_capability("write", "yes", atom.confidence, evidence)
        if atom.action == "token_permission" and atom.value == "id-token:write":
            builder.add_capability("escalate", "yes", atom.confidence, evidence)
            builder.add_gap(
                "OIDC provider trust policy and GitHub environment protections require "
                "live/API review."
            )
        if atom.action == "credential":
            builder.add_capability("read", "possible", atom.confidence, evidence)
        if atom.action == "runner" and atom.resource == "self_hosted_runner":
            builder.add_capability("escalate", "possible", atom.confidence, evidence)
        if atom.action == "cloud_deploy":
            builder.add_capability("deploy", "yes", atom.confidence, evidence)
            builder.add_capability("send", "possible", atom.confidence, evidence)
        if atom.action == "deployment_environment":
            builder.add_evidence(evidence)
    if "pull_request_target" in text:
        builder.add_capability(
            "escalate",
            "possible",
            "medium",
            "Workflow uses pull_request_target; token/secrets exposure depends on job "
            "checkout and conditions.",
        )


def _analyze_mcp_config(builder: SimulationBuilder, text: str) -> None:
    builder.add_input("mcp_config", "snapshot")
    atoms = extract_atoms(".mcp.json", text)
    if not atoms:
        builder.add_gap("MCP config snippet could not be parsed into MCP permission atoms.")
        return
    for atom in atoms:
        evidence = atom.evidence or f"{atom.action}: {atom.value}"
        if atom.action == "remote_server":
            builder.add_capability("send", "yes", atom.confidence, evidence)
        elif atom.action == "launch":
            builder.add_capability("read", "possible", "medium", evidence)
            builder.add_capability("write", "possible", "medium", evidence)
            builder.add_gap(
                "Launched MCP server runtime tools require MCPAudit connected or "
                "supplied tool-schema evidence."
            )
        elif atom.action == "credential":
            builder.add_capability("read", "possible", atom.confidence, evidence)
        elif atom.action == "tool_allowlist":
            level: CapabilityLevel = "possible"
            builder.add_capability("read", level, atom.confidence, evidence)
            builder.add_capability("write", level, atom.confidence, evidence)
            builder.add_capability("send", level, atom.confidence, evidence)
            if atom.value == "*":
                builder.add_capability("escalate", "possible", "medium", evidence)
                builder.add_gap(
                    "Broad MCP tool allowlist requires live tools/list or MCPAudit JSON "
                    "to know exact tools."
                )


def _analyze_mcpaudit_json(builder: SimulationBuilder, text: str) -> None:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        builder.add_input("mcpaudit_json", "snapshot", status="parse_error")
        builder.add_gap("MCPAudit JSON could not be parsed.")
        return
    builder.add_input("mcpaudit_json", "snapshot")
    permission_categories = sorted(_walk_permission_categories(payload))
    if not permission_categories:
        builder.add_gap("MCPAudit JSON did not include recognizable permission categories.")
        return
    category_map: dict[str, tuple[CapabilityName, CapabilityLevel, str]] = {
        "file_read": ("read", "yes", "high"),
        "file_write": ("write", "yes", "high"),
        "network": ("send", "yes", "high"),
        "exfiltration": ("send", "yes", "high"),
        "destructive": ("escalate", "yes", "high"),
        "shell_execution": ("escalate", "yes", "high"),
    }
    for category in permission_categories:
        if category not in category_map:
            continue
        capability, level, confidence = category_map[category]
        builder.add_capability(
            capability,
            level,
            confidence,
            f"MCPAudit reported permission category `{category}`",
        )
    if _json_contains_rule(payload, ("MCP013", "MCP014", "MCP018", "MCP019")):
        builder.add_capability(
            "bypass",
            "possible",
            "medium",
            "MCPAudit JSON includes trifecta or escalation/rug-pull rule IDs.",
        )


def _analyze_subagent(builder: SimulationBuilder, text: str) -> None:
    frontmatter = _parse_frontmatter(text)
    status = "parsed" if frontmatter is not None else "no_frontmatter"
    builder.add_input("subagent", "snapshot", status=status)
    if frontmatter is None:
        builder.add_gap(
            "Claude subagent frontmatter was not found; inherited tools are runtime-dependent."
        )
        return

    tools = frontmatter.get("tools")
    if tools is None:
        builder.add_gap(
            "Subagent tools are omitted; Claude Code runtime inheritance decides effective tools."
        )
    for tool in _tool_names(tools):
        for prefix, capabilities in SUBAGENT_TOOL_MAP:
            if tool == prefix or tool.startswith(f"{prefix}("):
                for capability in capabilities:
                    builder.add_capability(
                        capability,
                        "possible",
                        "medium",
                        f"Subagent declares tool `{tool}`",
                    )
        if tool.startswith("mcp__"):
            builder.add_capability(
                "send", "possible", "medium", f"Subagent declares MCP tool `{tool}`"
            )
            if any(
                token in tool.lower() for token in ("write", "create", "update", "delete", "send")
            ):
                builder.add_capability(
                    "write", "possible", "medium", f"Subagent declares MCP tool `{tool}`"
                )

    permission_mode = str(
        frontmatter.get("permissionMode") or frontmatter.get("permission_mode") or ""
    )
    if permission_mode:
        builder.add_evidence(f"Subagent permission mode `{permission_mode}`")
    if permission_mode.lower() in {"bypasspermissions", "dangerouslyskippermissions"}:
        builder.add_capability(
            "bypass",
            "yes",
            "high",
            f"Subagent permission mode `{permission_mode}` can bypass normal approval boundaries.",
        )
        builder.add_capability(
            "escalate",
            "possible",
            "medium",
            f"Subagent permission mode `{permission_mode}` changes effective autonomy.",
        )


def _analyze_hook_policy(builder: SimulationBuilder, text: str) -> None:
    builder.add_input("hook_policy", "snapshot")
    lowered = text.lower()
    if "pretooluse" in lowered or "permissionrequest" in lowered:
        builder.add_evidence("Hook snapshot includes PreToolUse or PermissionRequest guardrails.")
    else:
        builder.add_gap("Hook snapshot does not show PreToolUse or PermissionRequest guardrails.")
    if "disabled.json" in lowered or "hooks_disable" in lowered:
        builder.add_capability(
            "bypass",
            "possible",
            "medium",
            "Hook snapshot references hook disable controls; effective write access "
            "needs runtime review.",
        )
    if '"default": "deny"' in lowered or 'default = "deny"' in lowered:
        builder.add_evidence("Hook/policy snapshot includes default-deny egress posture.")
    if "allow_hosts" in lowered or "allow_connectors" in lowered:
        builder.add_evidence("Hook/policy snapshot includes destination or connector allowlists.")
    if "sensitive_paths" in lowered or "project_secret_basenames" in lowered:
        builder.add_evidence(
            "Hook/policy snapshot includes sensitive-path or project-secret read controls."
        )
    if "permissiondecision" not in lowered and "deny" not in lowered:
        builder.add_gap("Hook snapshot lacks explicit deny/decision evidence.")


def _parse_frontmatter(text: str) -> dict[str, Any] | None:
    if not text.startswith("---"):
        return None
    parts = text.split("---", 2)
    if len(parts) < 3:
        return None
    try:
        parsed = yaml.safe_load(parts[1]) or {}
    except yaml.YAMLError:
        return None
    return parsed if isinstance(parsed, dict) else None


def _tool_names(value: object) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return tuple(item.strip() for item in value.split(",") if item.strip())
    if isinstance(value, list):
        return tuple(str(item).strip() for item in value if str(item).strip())
    return ()


def _walk_permission_categories(value: object) -> set[str]:
    categories: set[str] = set()
    if isinstance(value, dict):
        for key, item in value.items():
            if key in {"category", "permission_category"} and isinstance(item, str):
                categories.add(item)
            elif key in {"permission_categories", "top_permissions"}:
                categories.update(_category_values(item))
            else:
                categories.update(_walk_permission_categories(item))
    elif isinstance(value, list):
        for item in value:
            categories.update(_walk_permission_categories(item))
    return categories


def _category_values(value: object) -> set[str]:
    if isinstance(value, str):
        return {item.strip() for item in re.split(r"[, ]+", value) if item.strip()}
    if isinstance(value, list):
        return {str(item).strip() for item in value if str(item).strip()}
    if isinstance(value, dict):
        return {str(key).strip() for key, enabled in value.items() if enabled}
    return set()


def _json_contains_rule(value: object, rule_ids: tuple[str, ...]) -> bool:
    text = json.dumps(value, sort_keys=True)
    return any(rule_id in text for rule_id in rule_ids)


def _github_probe_context(payload: object) -> str:
    if not isinstance(payload, dict):
        return ""
    parts = []
    repo = payload.get("repository") or payload.get("repository_full_name")
    sha = payload.get("head_sha") or payload.get("sha")
    pull_number = payload.get("pull_number") or payload.get("pr_number")
    if repo:
        parts.append(f"repository `{repo}`")
    if sha:
        parts.append(f"sha `{sha}`")
    if pull_number:
        parts.append(f"PR `#{pull_number}`")
    return f" for {', '.join(str(part) for part in parts)}" if parts else ""


def _github_live_probe_validation_errors(
    options: GitHubActionsLiveProbeOptions,
) -> list[str]:
    errors: list[str] = []
    if GITHUB_API_HOST not in options.allowed_hosts:
        errors.append(
            "GitHub Actions live probe is blocked because api.github.com is not allowlisted."
        )
    if not options.repository:
        errors.append("GitHub Actions live probe requires --github-repository owner/repo.")
    elif not GITHUB_REPOSITORY_RE.fullmatch(options.repository):
        errors.append("GitHub Actions live probe repository must be in owner/repo form.")
    if not options.ref:
        errors.append("GitHub Actions live probe requires --github-ref branch, tag, or SHA.")
    if options.timeout_seconds <= 0 or options.timeout_seconds > MAX_GITHUB_TIMEOUT_SECONDS:
        errors.append(
            "GitHub Actions live probe timeout must be greater than 0 and no more than "
            f"{MAX_GITHUB_TIMEOUT_SECONDS:g} seconds."
        )
    if options.token_env is not None and not re.fullmatch(
        r"[A-Za-z_][A-Za-z0-9_]*",
        options.token_env,
    ):
        errors.append("GitHub Actions live probe token env name is not a valid environment key.")
    return errors


def _github_pull_resolver_validation_errors(
    options: GitHubActionsLiveProbeOptions,
) -> list[str]:
    errors: list[str] = []
    if GITHUB_API_HOST not in options.allowed_hosts:
        errors.append(
            "GitHub pull request head resolution is blocked because api.github.com is not "
            "allowlisted."
        )
    if not options.repository:
        errors.append(
            "GitHub pull request head resolution requires --github-repository owner/repo."
        )
    elif not GITHUB_REPOSITORY_RE.fullmatch(options.repository):
        errors.append("GitHub pull request head resolution repository must be in owner/repo form.")
    if options.pull_number is None:
        errors.append("GitHub pull request head resolution requires --github-pull-number.")
    elif options.pull_number <= 0:
        errors.append("GitHub pull request number must be greater than 0.")
    if options.timeout_seconds <= 0 or options.timeout_seconds > MAX_GITHUB_TIMEOUT_SECONDS:
        errors.append(
            "GitHub pull request head resolution timeout must be greater than 0 and no more "
            f"than {MAX_GITHUB_TIMEOUT_SECONDS:g} seconds."
        )
    if options.token_env is not None and not re.fullmatch(
        r"[A-Za-z_][A-Za-z0-9_]*",
        options.token_env,
    ):
        errors.append("GitHub pull request head resolution token env name is invalid.")
    return errors


def resolve_github_pull_head_sha(options: GitHubActionsLiveProbeOptions) -> GitHubPullResolution:
    validation_errors = _github_pull_resolver_validation_errors(options)
    if validation_errors:
        raise GitHubProbeError(validation_errors[0])
    assert options.repository is not None
    assert options.pull_number is not None

    token = _read_github_probe_token(options)
    owner_repo = urllib.parse.quote(options.repository, safe="/")
    pull_url = f"https://{GITHUB_API_HOST}/repos/{owner_repo}/pulls/{options.pull_number}"
    payload = _github_api_get_json(pull_url, options, token)
    head = payload.get("head")
    base = payload.get("base")
    if not isinstance(head, dict):
        raise GitHubProbeError(
            "GitHub pull request head resolution did not return head metadata; "
            "no mutation was attempted."
        )
    sha = head.get("sha")
    if not isinstance(sha, str) or not sha:
        raise GitHubProbeError(
            "GitHub pull request head resolution did not return a head SHA; "
            "no mutation was attempted."
        )
    return GitHubPullResolution(
        head_sha=sha,
        head_repository=_github_pull_repo_full_name(head),
        base_repository=_github_pull_repo_full_name(base),
    )


def _github_pull_repo_full_name(value: object) -> str | None:
    if not isinstance(value, dict):
        return None
    repo = value.get("repo")
    if not isinstance(repo, dict):
        return None
    full_name = repo.get("full_name")
    return full_name if isinstance(full_name, str) and full_name else None


def fetch_github_actions_readonly_metadata(
    options: GitHubActionsLiveProbeOptions,
) -> dict[str, Any]:
    validation_errors = _github_live_probe_validation_errors(options)
    if validation_errors:
        raise GitHubProbeError(validation_errors[0])
    assert options.repository is not None
    assert options.ref is not None

    token = _read_github_probe_token(options)
    owner_repo = urllib.parse.quote(options.repository, safe="/")
    encoded_ref = urllib.parse.quote(options.ref, safe="")
    check_runs_url = (
        f"https://{GITHUB_API_HOST}/repos/{owner_repo}/commits/{encoded_ref}/check-runs"
    )
    workflow_runs_url = (
        f"https://{GITHUB_API_HOST}/repos/{owner_repo}/actions/runs?"
        f"head_sha={encoded_ref}&per_page=8"
    )
    check_payload = _github_api_get_json(check_runs_url, options, token)
    workflow_payload = _github_api_get_json(workflow_runs_url, options, token)
    return {
        "repository": options.repository,
        "head_sha": options.ref,
        "pull_number": options.pull_number,
        "check_runs": _github_check_runs(check_payload),
        "workflow_runs": _github_workflow_runs(workflow_payload),
    }


def _read_github_probe_token(options: GitHubActionsLiveProbeOptions) -> str | None:
    if not options.token_env:
        return None
    token = os.environ.get(options.token_env)
    if not token:
        raise GitHubProbeError(
            f"GitHub Actions live probe token source `{options.token_source()}` was not set."
        )
    return token


def _github_api_get_json(
    url: str,
    options: GitHubActionsLiveProbeOptions,
    token: str | None,
) -> dict[str, Any]:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in options.allowed_hosts:
        raise GitHubProbeError("GitHub Actions live probe blocked a non-allowlisted URL.")
    request = urllib.request.Request(
        url,
        headers=_github_api_headers(token),
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=options.timeout_seconds) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise GitHubProbeError(_github_http_error_message(exc)) from exc
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        raise GitHubProbeError(
            "GitHub Actions live probe read failed before usable metadata was returned; "
            "no mutation was attempted."
        ) from exc
    return payload if isinstance(payload, dict) else {}


def _github_http_error_message(exc: urllib.error.HTTPError) -> str:
    rate_limited = exc.code in {403, 429} and exc.headers.get("x-ratelimit-remaining") == "0"
    if rate_limited:
        return (
            "GitHub Actions live probe read was rate-limited by GitHub HTTP "
            f"{exc.code}; no mutation was attempted."
        )
    return (
        "GitHub Actions live probe read failed with GitHub HTTP "
        f"{exc.code}; no mutation was attempted."
    )


def _github_api_headers(token: str | None) -> dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "agent-permission-diff-bot",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _github_check_runs(payload: object) -> list[dict[str, Any]]:
    if not isinstance(payload, dict):
        return []
    runs = payload.get("check_runs")
    return [item for item in runs if isinstance(item, dict)] if isinstance(runs, list) else []


def _github_workflow_runs(payload: object) -> list[dict[str, Any]]:
    if not isinstance(payload, dict):
        return []
    runs = payload.get("workflow_runs")
    return [item for item in runs if isinstance(item, dict)] if isinstance(runs, list) else []


def _format_github_run(kind: str, run: dict[str, Any]) -> str:
    name = run.get("name") or run.get("display_title") or run.get("workflow_name") or "unnamed"
    status = run.get("status") or "unknown"
    conclusion = run.get("conclusion") or "unknown"
    return f"GitHub Actions {kind} `{name}` reported status `{status}` conclusion `{conclusion}`."


def _command_has_unresolved_destination(command: str) -> bool:
    try:
        tokens = shlex.split(command)
    except ValueError:
        tokens = command.split()
    return any(
        "$" in token and any(prefix in token for prefix in ("http", "git@", "ssh"))
        for token in tokens
    )


def _stronger_level(left: CapabilityLevel, right: CapabilityLevel) -> CapabilityLevel:
    order = {"no": 0, "unknown": 1, "possible": 2, "yes": 3}
    return right if order[right] > order[left] else left


def _weaker_confidence(left: str, right: str) -> str:
    order = {"high": 3, "medium": 2, "low": 1}
    return right if order.get(right, 1) < order.get(left, 1) else left


def _compact(value: str, limit: int = 140) -> str:
    collapsed = " ".join(value.split())
    if len(collapsed) <= limit:
        return collapsed
    return f"{collapsed[: limit - 3]}..."
