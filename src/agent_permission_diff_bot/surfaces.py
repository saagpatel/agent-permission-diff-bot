from __future__ import annotations

import json
import re
from collections.abc import Mapping
from pathlib import PurePosixPath
from urllib.parse import urlparse

import yaml

from agent_permission_diff_bot.model import PermissionAtom

WORKFLOW_GLOBS = (".github/workflows/*.yml", ".github/workflows/*.yaml")
MCP_PATHS = (
    ".mcp.json",
    ".vscode/mcp.json",
    ".cursor/mcp.json",
    ".windsurf/mcp.json",
    ".github/copilot/mcp.json",
)
EGRESS_PATH_NAMES = {
    "mcp-gate-policy.json",
    "egress-allow-list.json",
    "egress-policy.json",
}
INSTRUCTION_PATHS = {
    "AGENTS.md",
    "CLAUDE.md",
    "GEMINI.md",
    ".github/copilot-instructions.md",
    ".cursor/rules",
    ".windsurfrules",
}
INSTRUCTION_PREFIXES = (".github/instructions/", ".cursor/rules/")

SECRET_REF_RE = re.compile(r"secrets\.([A-Za-z_][A-Za-z0-9_]*)")
HOST_RE = re.compile(r"https?://[^\s\"')>]+")
WRITE_VERBS = (
    "create",
    "copy",
    "upload",
    "update",
    "delete",
    "merge",
    "push",
    "publish",
    "deploy",
    "send",
    "archive",
    "label",
    "close",
)
DEPLOY_ACTION_HINTS = (
    "pypa/gh-action-pypi-publish",
    "cloudflare/",
    "vercel/",
    "amondnet/vercel-action",
    "actions/deploy-pages",
    "docker/login-action",
    "docker/build-push-action",
)
WEAKENING_INSTRUCTION_RE = re.compile(
    r"\b(skip|bypass|ignore|disable|avoid)\b.{0,60}\b(test|review|approval|secret|"
    r"permission|policy|guard|hook|check)\b",
    re.IGNORECASE | re.DOTALL,
)


def is_interesting_path(path: str) -> bool:
    normalized = _normalize(path)
    if _is_workflow(normalized):
        return True
    if _is_mcp_config(normalized):
        return True
    if _is_instruction(normalized):
        return True
    return PurePosixPath(normalized).name in EGRESS_PATH_NAMES


def extract_atoms(path: str, text: str) -> list[PermissionAtom]:
    normalized = _normalize(path)
    if _is_workflow(normalized):
        return _extract_workflow_atoms(normalized, text)
    if _is_mcp_config(normalized):
        return _extract_mcp_atoms(normalized, text)
    if _is_instruction(normalized):
        return _extract_instruction_atoms(normalized, text)
    if PurePosixPath(normalized).name in EGRESS_PATH_NAMES:
        return _extract_egress_atoms(normalized, text)
    return []


def _extract_workflow_atoms(path: str, text: str) -> list[PermissionAtom]:
    data = _load_yaml(text)
    if not isinstance(data, Mapping):
        return []

    atoms: list[PermissionAtom] = []
    triggers = _workflow_triggers(_mapping_get(data, "on"))
    secret_refs = tuple(sorted(set(SECRET_REF_RE.findall(text))))

    atoms.extend(
        _permission_atoms(path, "workflow", data.get("permissions"), triggers, secret_refs)
    )

    jobs = data.get("jobs")
    if isinstance(jobs, Mapping):
        for job_id, job in jobs.items():
            if not isinstance(job, Mapping):
                continue
            actor = f"job:{job_id}"
            atoms.extend(
                _permission_atoms(path, actor, job.get("permissions"), triggers, secret_refs)
            )
            atoms.extend(_runner_atoms(path, actor, job.get("runs-on"), triggers))
            atoms.extend(_environment_atoms(path, actor, job.get("environment"), triggers))
            atoms.extend(_step_atoms(path, actor, job.get("steps"), triggers, secret_refs))

    for key in secret_refs:
        atoms.append(
            PermissionAtom(
                surface="actions",
                actor="workflow",
                action="credential",
                verb="reference",
                resource="github_secret",
                value=key,
                path=path,
                trigger=",".join(triggers),
                credential_keys=(key,),
                evidence=f"references secrets.{key}",
            )
        )

    return atoms


def _permission_atoms(
    path: str,
    actor: str,
    permissions: object,
    triggers: tuple[str, ...],
    secret_refs: tuple[str, ...],
) -> list[PermissionAtom]:
    atoms: list[PermissionAtom] = []
    if permissions is None:
        return atoms
    if isinstance(permissions, str):
        atoms.append(
            PermissionAtom(
                surface="actions",
                actor=actor,
                action="token_permission",
                verb=permissions,
                resource="GITHUB_TOKEN",
                value=permissions,
                path=path,
                trigger=",".join(triggers),
                credential_keys=secret_refs,
                evidence=f"permissions: {permissions}",
            )
        )
        return atoms
    if isinstance(permissions, Mapping):
        for scope, level in permissions.items():
            atoms.append(
                PermissionAtom(
                    surface="actions",
                    actor=actor,
                    action="token_permission",
                    verb=str(level),
                    resource=str(scope),
                    value=f"{scope}:{level}",
                    path=path,
                    trigger=",".join(triggers),
                    credential_keys=secret_refs,
                    evidence=f"permissions.{scope}: {level}",
                )
            )
    return atoms


def _runner_atoms(
    path: str,
    actor: str,
    runs_on: object,
    triggers: tuple[str, ...],
) -> list[PermissionAtom]:
    if runs_on is None:
        return []
    value = _stringify(runs_on)
    lower = value.lower()
    confidence = "high"
    resource = "github_hosted_runner"
    if "self-hosted" in lower:
        resource = "self_hosted_runner"
    if "pull_request.head.repo.fork" in value and (
        "ubuntu-latest" in value or "macos-latest" in value
    ):
        confidence = "medium"
    return [
        PermissionAtom(
            surface="actions",
            actor=actor,
            action="runner",
            verb="execute",
            resource=resource,
            value=value,
            path=path,
            trigger=",".join(triggers),
            confidence=confidence,
            evidence=f"runs-on: {value}",
        )
    ]


def _environment_atoms(
    path: str,
    actor: str,
    environment: object,
    triggers: tuple[str, ...],
) -> list[PermissionAtom]:
    if environment is None:
        return []
    value = _stringify(environment)
    return [
        PermissionAtom(
            surface="actions",
            actor=actor,
            action="deployment_environment",
            verb="use",
            resource="environment",
            value=value,
            path=path,
            trigger=",".join(triggers),
            evidence=f"environment: {value}",
        )
    ]


def _step_atoms(
    path: str,
    actor: str,
    steps: object,
    triggers: tuple[str, ...],
    secret_refs: tuple[str, ...],
) -> list[PermissionAtom]:
    if not isinstance(steps, list):
        return []
    atoms: list[PermissionAtom] = []
    for step in steps:
        if not isinstance(step, Mapping):
            continue
        uses = str(step.get("uses", ""))
        run = str(step.get("run", ""))
        lower_uses = uses.lower()
        lower_run = run.lower()
        if any(hint in lower_uses for hint in DEPLOY_ACTION_HINTS) or any(
            word in lower_run for word in ("deploy", "publish", "wrangler", "vercel", "pypi")
        ):
            atoms.append(
                PermissionAtom(
                    surface="actions",
                    actor=actor,
                    action="cloud_deploy",
                    verb="deploy",
                    resource="cloud_or_registry",
                    value=uses or _compact(run),
                    path=path,
                    trigger=",".join(triggers),
                    credential_keys=secret_refs,
                    evidence=f"deploy/publish step: {uses or _compact(run)}",
                )
            )
    return atoms


def _extract_mcp_atoms(path: str, text: str) -> list[PermissionAtom]:
    data = _load_json(text)
    if not isinstance(data, Mapping):
        return []
    servers = data.get("mcpServers") or data.get("servers")
    if not isinstance(servers, Mapping):
        return []

    atoms: list[PermissionAtom] = []
    for server_name, server in servers.items():
        if not isinstance(server, Mapping):
            continue
        actor = f"mcp:{server_name}"
        env_keys = _keys(server.get("env"))
        header_keys = _keys(server.get("headers"))
        credential_keys = tuple(sorted((*env_keys, *header_keys)))
        url = str(server.get("url", ""))
        command = str(server.get("command", ""))
        args = _stringify(server.get("args", ""))
        hosts = tuple(sorted(_hosts_from_text(" ".join((url, args)))))

        if url:
            atoms.append(
                PermissionAtom(
                    surface="mcp",
                    actor=actor,
                    action="remote_server",
                    verb="connect",
                    resource="url",
                    value=url,
                    path=path,
                    credential_keys=credential_keys,
                    egress_hosts=hosts,
                    evidence=f"MCP server URL {url}",
                )
            )
        if command or args:
            atoms.append(
                PermissionAtom(
                    surface="mcp",
                    actor=actor,
                    action="launch",
                    verb="execute",
                    resource="command",
                    value=_compact(f"{command} {args}".strip()),
                    path=path,
                    credential_keys=credential_keys,
                    egress_hosts=hosts,
                    evidence=f"MCP launch {command} {args}".strip(),
                )
            )
        for key in credential_keys:
            atoms.append(
                PermissionAtom(
                    surface="mcp",
                    actor=actor,
                    action="credential",
                    verb="reference",
                    resource="env_or_header_key",
                    value=key,
                    path=path,
                    credential_keys=(key,),
                    evidence=f"MCP credential key {key}",
                )
            )
        tools = server.get("tools")
        if tools == ["*"] or tools == "*":
            atoms.append(
                PermissionAtom(
                    surface="mcp",
                    actor=actor,
                    action="tool_allowlist",
                    verb="allow",
                    resource="tools",
                    value="*",
                    path=path,
                    credential_keys=credential_keys,
                    egress_hosts=hosts,
                    evidence='MCP tools allowlist includes "*"',
                )
            )
        elif isinstance(tools, list):
            for tool in tools:
                atoms.append(
                    PermissionAtom(
                        surface="mcp",
                        actor=actor,
                        action="tool_allowlist",
                        verb="allow",
                        resource="tools",
                        value=str(tool),
                        path=path,
                        credential_keys=credential_keys,
                        egress_hosts=hosts,
                        evidence=f"MCP tool allowlist includes {tool}",
                    )
                )
    return atoms


def _extract_egress_atoms(path: str, text: str) -> list[PermissionAtom]:
    data = _load_json(text)
    if not isinstance(data, Mapping):
        return []
    egress = data.get("egress") if isinstance(data.get("egress"), Mapping) else data
    if not isinstance(egress, Mapping):
        return []

    atoms: list[PermissionAtom] = []
    for key in ("allow_hosts", "multi_tenant_hosts"):
        for host in _list_values(egress.get(key)):
            atoms.append(
                PermissionAtom(
                    surface="egress",
                    actor="policy",
                    action=key,
                    verb="allow",
                    resource="host",
                    value=host,
                    path=path,
                    egress_hosts=(host,),
                    evidence=f"{key}: {host}",
                )
            )
    for connector in _list_values(egress.get("allow_connectors")):
        verb = "write" if any(word in connector.lower() for word in WRITE_VERBS) else "allow"
        atoms.append(
            PermissionAtom(
                surface="egress",
                actor="policy",
                action="allow_connectors",
                verb=verb,
                resource="connector",
                value=connector,
                path=path,
                evidence=f"allow_connectors: {connector}",
            )
        )
    for glob in _list_values(egress.get("network_name_globs")):
        atoms.append(
            PermissionAtom(
                surface="egress",
                actor="policy",
                action="network_name_glob",
                verb="match",
                resource="tool_name",
                value=glob,
                path=path,
                evidence=f"network_name_globs: {glob}",
            )
        )
    return atoms


def _extract_instruction_atoms(path: str, text: str) -> list[PermissionAtom]:
    action = "instruction_authority"
    evidence = "agent instruction file changed"
    confidence = "medium"
    if WEAKENING_INSTRUCTION_RE.search(text):
        action = "instruction_weakening"
        evidence = "instruction mentions bypassing tests/review/approval/policy-like controls"
        confidence = "high"
    return [
        PermissionAtom(
            surface="instructions",
            actor="agent",
            action=action,
            verb="trust",
            resource="agent_instructions",
            value=path,
            path=path,
            confidence=confidence,
            evidence=evidence,
        )
    ]


def _workflow_triggers(value: object) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    if isinstance(value, list):
        return tuple(str(item) for item in value)
    if isinstance(value, Mapping):
        return tuple(str(key) for key in value)
    return (str(value),)


def _mapping_get(data: Mapping[object, object], key: str) -> object:
    if key in data:
        return data[key]
    if key == "on" and True in data:
        return data[True]
    return None


def _is_workflow(path: str) -> bool:
    return path.startswith(".github/workflows/") and path.endswith((".yml", ".yaml"))


def _is_mcp_config(path: str) -> bool:
    return path in MCP_PATHS or path.endswith("/mcp.json") or path.endswith(".mcp.json")


def _is_instruction(path: str) -> bool:
    return path in INSTRUCTION_PATHS or any(
        path.startswith(prefix) for prefix in INSTRUCTION_PREFIXES
    )


def _load_yaml(text: str) -> object:
    try:
        return yaml.safe_load(text)
    except yaml.YAMLError:
        return None


def _load_json(text: str) -> object:
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def _keys(value: object) -> tuple[str, ...]:
    if isinstance(value, Mapping):
        return tuple(sorted(str(key) for key in value))
    return ()


def _list_values(value: object) -> tuple[str, ...]:
    if isinstance(value, list):
        return tuple(str(item) for item in value)
    if isinstance(value, str):
        return (value,)
    return ()


def _hosts_from_text(text: str) -> set[str]:
    hosts: set[str] = set()
    for match in HOST_RE.findall(text):
        parsed = urlparse(match)
        if parsed.hostname:
            hosts.add(parsed.hostname)
    return hosts


def _stringify(value: object) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return ",".join(str(item) for item in value)
    if isinstance(value, Mapping):
        return json.dumps(value, sort_keys=True)
    return str(value)


def _compact(value: str, limit: int = 140) -> str:
    collapsed = " ".join(value.split())
    if len(collapsed) <= limit:
        return collapsed
    return f"{collapsed[: limit - 3]}..."


def _normalize(path: str) -> str:
    normalized = path.strip().replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    return normalized
