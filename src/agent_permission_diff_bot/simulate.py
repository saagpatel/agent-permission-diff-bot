from __future__ import annotations

import json
import re
import shlex
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
    live_probe_needed: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "mode": self.mode,
            "safety_boundary": self.safety_boundary,
            "inputs": [item.to_dict() for item in self.inputs],
            "capabilities": {name: self.capabilities[name].to_dict() for name in CAPABILITIES},
            "deterministic_evidence": self.deterministic_evidence,
            "live_probe_needed": self.live_probe_needed,
        }


class SimulationBuilder:
    def __init__(self) -> None:
        self.inputs: list[SimulationInput] = []
        self.capabilities = {name: CapabilityAssessment(capability=name) for name in CAPABILITIES}
        self.deterministic_evidence: list[str] = []
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
) -> SimulationReport:
    builder = SimulationBuilder()
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
    if not builder.inputs:
        builder.add_gap("No simulation inputs were supplied.")
    if not any(assessment.level != "no" for assessment in builder.capabilities.values()):
        builder.add_gap("Static inputs did not expose a concrete capability expansion.")
    return builder.build()


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

    lines.extend(["", "## Live Probe Needed", ""])
    if report.live_probe_needed:
        lines.extend(f"- {item}" for item in report.live_probe_needed)
    else:
        lines.append("- None for the supplied static evidence.")

    lines.append("")
    return "\n".join(lines)


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
