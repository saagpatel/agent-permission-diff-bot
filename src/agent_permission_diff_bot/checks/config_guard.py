"""Agent Config Guard: what a pull request now lets an agent do.

The check runs the existing permission diff engine on two in-memory snapshots
(base and head), then rewrites each finding for a reviewer: the change, what it
now allows, and one suggested fix. Allow rules are expanded with the vendored
Range engine, which knows which subcommands and flags of a program reach further
than the rule's text suggests. Everything here is static: no network, no
credentials, nothing executed.
"""

from __future__ import annotations

import difflib
import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import replace
from pathlib import PurePosixPath

import yaml

from agent_permission_diff_bot._vendor.therange import engine as range_engine
from agent_permission_diff_bot._vendor.therange.claude_rules import (
    parse_allowed_tools,
    parse_rule,
)
from agent_permission_diff_bot._vendor.therange.codex_rules import (
    RulesParseError,
    parse_rules_text,
)
from agent_permission_diff_bot._vendor.therange.kb import load_kb
from agent_permission_diff_bot._vendor.therange.model import Rule, Source
from agent_permission_diff_bot.checks.model import CheckFinding, CheckResult, rank
from agent_permission_diff_bot.engine import build_report
from agent_permission_diff_bot.model import Finding, PermissionAtom, PermissionChange, Severity
from agent_permission_diff_bot.persistence import MODE_RANKS, project_config_kind
from agent_permission_diff_bot.surfaces import _is_instruction, is_interesting_path

MAX_ALLOWS = 3

_RANGE_SEVERITY = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
}

_HOOK_WHEN = {
    "sessionstart": "every time an agent session starts in this repo, before anyone types",
    "session_start": "every time an agent session starts in this repo, before anyone types",
    "userpromptsubmit": "on every prompt, and it can rewrite or block the prompt",
    "pretooluse": "before each matching tool call, and it can approve the call without asking",
    "permissionrequest": "on each permission prompt, and it can answer the prompt itself",
    "posttooluse": "after each matching tool call",
    "stop": "whenever the agent finishes a turn, and it can keep the agent going",
    "subagentstop": "whenever a subagent finishes",
    "precompact": "before the conversation is compacted",
    "sessionend": "when a session ends",
    "notification": "on every agent notification",
    "statusline": "continuously, to draw the status line",
    "apikeyhelper": "whenever the agent needs an API key, with credentials in reach",
    "awsauthrefresh": "whenever AWS credentials refresh, with credentials in reach",
    "awscredentialexport": "whenever AWS credentials are exported, with credentials in reach",
    "otelheadershelper": "whenever telemetry headers are built",
}

_MODE_TEXT = {
    "bypassPermissions": "Every tool call runs without a prompt; only deny rules still apply.",
    "acceptEdits": "File edits run without a prompt.",
    "dontAsk": "Tools that are not pre-approved are refused instead of asked about.",
    "danger-full-access": "Commands run with no sandbox: full disk and network access.",
    "workspace-write": "Commands may write anywhere in the workspace.",
    "never": "The agent never asks before running a command.",
    "on-failure": "The agent asks only after a sandboxed command fails.",
}

# Line-level and plural-aware, unlike the engine's whole-file APD006 pattern.
_SKIP_CHECK_RE = re.compile(
    r"(\b(skip|bypass|ignore|disable|avoid|suppress|silence)\b|\bdo(n'?t| not)\s+run\b|"
    r"\bnever\s+run\b|\bno need to (run|wait for)\b|\bwithout (running|waiting for)\b)"
    r".{0,60}\b(tests?|reviews?|approvals?|secrets? scan\w*|permissions?|polic(y|ies)|"
    r"guard(rail)?s?|hooks?|checks?|lint\w*|ci|type.?check\w*|verification|pre-commit)\b"
    r"|--no-verify\b|--dangerously-skip-permissions\b",
    re.IGNORECASE,
)
_ABSORBED_BY_HOOK = {"APD011", "APD012", "APD015", "APD105"}
_SKILL_RE = re.compile(r"(^|/)\.claude/(commands|skills|agents)/.+\.md$", re.IGNORECASE)
_CODEX_RULES_RE = re.compile(r"(^|/)\.codex/rules/[^/]+\.rules$", re.IGNORECASE)
_MATCHER_RE = re.compile(r'"matcher":\s*"([^"]*)"')


def is_guard_path(path: str) -> bool:
    """Files Config Guard reads: the engine's surfaces plus skill and Codex rule files."""
    return (
        project_config_kind(path) is not None
        or is_interesting_path(path)
        or bool(_SKILL_RE.search(path))
        or bool(_CODEX_RULES_RE.search(path))
    )


def run_config_guard(base: Mapping[str, str], head: Mapping[str, str]) -> CheckResult:
    """Compare two snapshots ({path: text}) and explain what the head now allows."""
    result = CheckResult(check="config-guard")
    report = build_report("base", dict(base), "head", dict(head))
    findings: dict[tuple[str, ...], CheckFinding] = {}

    def keep(key: tuple[str, ...], finding: CheckFinding | None) -> None:
        if finding is None or finding.severity < Severity.MEDIUM:
            return
        current = findings.get(key)
        if current is None or finding.severity > current.severity:
            findings[key] = finding

    handled_actions = {"permission_rule", "permission_mode", "auto_hook", "instruction_weakening"}
    for engine_finding in report.findings:
        atoms = [change.atom for change in engine_finding.changes]
        if atoms and all(atom.action in handled_actions for atom in atoms):
            continue
        if any(_is_mcp_server_atom(atom) for atom in atoms):
            continue
        keep(
            ("engine", engine_finding.rule_id, *engine_finding.paths(), engine_finding.title),
            _from_engine(engine_finding, head),
        )

    for change in report.changes:
        atom = change.atom
        if atom.action == "permission_rule":
            if change.kind == "added" and atom.resource == "allow":
                rule = parse_rule(atom.value, "allow", _source(atom.path))
                keep(("allow", atom.path, atom.value), _allow_finding(rule, atom.path, head))
            elif change.kind == "removed" and atom.resource == "deny":
                if not _still_denied(atom, report.changes):
                    keep(("deny", atom.path, atom.value), _removed_deny(atom, head))
        elif atom.action == "permission_mode" and change.kind == "added":
            keep(("mode", atom.path, atom.resource), _mode_finding(atom, report.changes, head))
        elif atom.action == "auto_hook" and change.kind == "added":
            keep(("hook", atom.path, atom.trigger, atom.value), _hook_finding(atom, head))
        elif _is_mcp_server_atom(atom) and change.kind == "added":
            name = _mcp_server_name(atom)
            keep(("mcp", atom.path, name), _mcp_finding(atom, name, report.changes, head))

    for finding in _instruction_findings(base, head):
        keep(("instruction", finding.path, str(finding.line)), finding)
    for key, finding in _rule_file_findings(base, head, result.notes):
        keep(key, finding)

    result.findings = rank(_fold_into_hooks(list(findings.values()), report.findings))
    return result


def _fold_into_hooks(findings: list[CheckFinding], engine: list[Finding]) -> list[CheckFinding]:
    """Report a hook once: its startup-payload findings become part of the hook entry."""
    hooks = [f for f in findings if f.rule_id == "CG004"]
    if not hooks:
        return findings
    folded: list[CheckFinding] = []
    absorbed: set[int] = set()
    for hook in hooks:
        command = hook.allows[0]
        severity = hook.severity
        extra: list[str] = []
        for index, other in enumerate(findings):
            if other.rule_id not in _ABSORBED_BY_HOOK or index in absorbed:
                continue
            source = next(
                (e for e in engine if e.rule_id == other.rule_id and e.title == other.title), None
            )
            evidence = " ".join(source.evidence) if source else " ".join(other.allows)
            if not any(word in evidence for word in _command_words(command)):
                continue
            absorbed.add(index)
            severity = max(severity, other.severity)
            extra.append(f"{other.title} ({other.rule_id}).")
        folded.append(replace(hook, severity=severity, allows=(*hook.allows, *extra[:2])))
    rest = [f for index, f in enumerate(findings) if f.rule_id != "CG004" and index not in absorbed]
    return folded + rest


def _command_words(allows_line: str) -> list[str]:
    match = re.search(r"`([^`]+)`", allows_line)
    words = match.group(1).split() if match else []
    return [w for w in words if "/" in w or "." in w] or words[:1]


# --- allow rules, expanded with the Range ------------------------------------------------


def _source(path: str, kind: str = "project settings") -> Source:
    if _CODEX_RULES_RE.search(path):
        return Source(agent="codex", kind=kind, label=path, path=path)
    return Source(agent="claude", kind=kind, label=path, path=path)


def _allow_finding(rule: Rule, path: str, head: Mapping[str, str]) -> CheckFinding | None:
    kb = load_kb()
    expanded = range_engine.analyze_rule(rule, kb)
    serious = [f for f in expanded if f.effective_severity != "info"]
    if not serious:
        return None
    suggestion = range_engine.suggest(rule, expanded, kb)
    severity = max(_RANGE_SEVERITY[f.effective_severity] for f in serious)
    allows = [_range_line(f.title, f.example) for f in serious[:MAX_ALLOWS]]
    if len(serious) > MAX_ALLOWS:
        allows.append(f"…and {len(serious) - MAX_ALLOWS} more reaches the Range knows about.")
    label = "allow rule" if rule.agent == "claude" else "Codex allow rule"
    return CheckFinding(
        check="config-guard",
        rule_id="CG001",
        severity=severity,
        title=f"New {label} `{rule.raw}`",
        path=path,
        line=_line_of(head.get(path, ""), rule.raw),
        allows=tuple(allows),
        fix=suggestion.text,
    )


def _range_line(title: str, example: str) -> str:
    example = example.strip()
    return f"{title}, e.g. `{example}`" if example else title


def _still_denied(atom: PermissionAtom, changes: Iterable[PermissionChange]) -> bool:
    for other in changes:
        other_atom = other.atom
        if (
            other.kind == "added"
            and other_atom.action == "permission_rule"
            and other_atom.resource == "deny"
            and other_atom.path == atom.path
            and other_atom.value in {atom.value, atom.value.split("(", 1)[0], "*"}
        ):
            return True
    return False


def _removed_deny(atom: PermissionAtom, head: Mapping[str, str]) -> CheckFinding:
    return CheckFinding(
        check="config-guard",
        rule_id="CG002",
        severity=Severity.HIGH,
        title=f"Deny rule `{atom.value}` removed",
        path=atom.path,
        line=None,
        allows=(f"The agent is no longer blocked from `{atom.value}`.",),
        fix="Keep the deny rule unless this action is meant to run without a prompt.",
    )


# --- permission modes ----------------------------------------------------------------------


def _mode_finding(
    atom: PermissionAtom, changes: Iterable[PermissionChange], head: Mapping[str, str]
) -> CheckFinding | None:
    ranks = MODE_RANKS.get(atom.resource, {})
    previous = [
        other.atom.value
        for other in changes
        if other.kind == "removed"
        and other.atom.path == atom.path
        and other.atom.resource == atom.resource
        and other.atom.action == "permission_mode"
    ]
    new_rank = ranks.get(atom.value)
    old_rank = ranks.get(previous[0]) if previous else None
    if new_rank is None:
        return None
    widening = new_rank > old_rank if old_rank is not None else new_rank > 1
    if not widening:
        return None
    severity = (
        Severity.CRITICAL
        if atom.value in {"bypassPermissions", "danger-full-access"}
        else Severity.HIGH
    )
    was = f" (was `{previous[0]}`)" if previous else ""
    return CheckFinding(
        check="config-guard",
        rule_id="CG003",
        severity=severity,
        title=f"`{atom.resource}` is now `{atom.value}`{was}",
        path=atom.path,
        line=_line_of(head.get(atom.path, ""), atom.value),
        allows=(_MODE_TEXT.get(atom.value, "The agent asks for approval less often."),),
        fix=(
            "Keep the committed default conservative and opt in per session "
            "(for example `--permission-mode` or a local, uncommitted setting)."
        ),
    )


# --- hooks ---------------------------------------------------------------------------------


def _hook_finding(atom: PermissionAtom, head: Mapping[str, str]) -> CheckFinding:
    event = atom.trigger or "hook"
    when = _HOOK_WHEN.get(event.lower(), f"on the `{event}` event")
    matcher = _MATCHER_RE.search(atom.scope)
    target = f" for tools matching `{matcher.group(1)}`" if matcher and matcher.group(1) else ""
    auto_start = event.lower() in {
        "sessionstart",
        "session_start",
        "statusline",
        "apikeyhelper",
        "awsauthrefresh",
        "awscredentialexport",
        "otelheadershelper",
    }
    approves = event.lower() in {"pretooluse", "permissionrequest", "userpromptsubmit"}
    severity = Severity.HIGH if auto_start or approves else Severity.MEDIUM
    allows = [f"Runs `{_short(atom.value)}` {when}{target}."]
    if auto_start:
        allows.append("Anyone who can change that command or script runs code on every machine.")
    return CheckFinding(
        check="config-guard",
        rule_id="CG004",
        severity=severity,
        title=f"New `{event}` hook",
        path=atom.path,
        line=_line_of(head.get(atom.path, ""), atom.value.split(" ", 1)[0]),
        allows=tuple(allows),
        fix=(
            "Point the hook at a script checked into this repo and reviewed like code; "
            "never download and run remote code from a hook."
        ),
    )


# --- MCP servers ---------------------------------------------------------------------------


def _is_mcp_server_atom(atom: PermissionAtom) -> bool:
    if atom.action in {"launch", "remote_server"} and ":mcp:" in f":{atom.actor}":
        return True
    return atom.action == "project_setting" and atom.resource in {
        "mcpServers",
        "enabledMcpjsonServers",
        "enableAllProjectMcpServers",
    }


def _mcp_server_name(atom: PermissionAtom) -> str:
    if atom.action == "project_setting":
        return atom.value
    return atom.actor.rsplit("mcp:", 1)[-1]


def _mcp_finding(
    atom: PermissionAtom, name: str, changes: Iterable[PermissionChange], head: Mapping[str, str]
) -> CheckFinding | None:
    if atom.action == "project_setting":
        if atom.resource == "enableAllProjectMcpServers":
            if atom.value.lower() not in {"true", "1"}:
                return None
            return CheckFinding(
                check="config-guard",
                rule_id="CG005",
                severity=Severity.HIGH,
                title="Every project MCP server is now approved automatically",
                path=atom.path,
                line=_line_of(head.get(atom.path, ""), "enableAllProjectMcpServers"),
                allows=(
                    "Any MCP server added to `.mcp.json` later starts without anyone approving it.",
                ),
                fix="List the servers you use in `enabledMcpjsonServers` instead.",
            )
        if atom.resource == "enabledMcpjsonServers":
            return CheckFinding(
                check="config-guard",
                rule_id="CG005",
                severity=Severity.MEDIUM,
                title=f"MCP server `{name}` is now approved automatically",
                path=atom.path,
                line=_line_of(head.get(atom.path, ""), name),
                allows=(f"`{name}` from `.mcp.json` starts without a trust prompt.",),
                fix="Approve it per user instead of in committed settings.",
            )
    launch: list[str] = []
    credentials: set[str] = set()
    for other in changes:
        other_atom = other.atom
        if (
            other.kind != "added"
            or other_atom.path != atom.path
            or _mcp_server_name(other_atom) != name
        ):
            continue
        credentials.update(other_atom.credential_keys)
        if other_atom.action == "launch":
            command = _short(other_atom.value.replace(",", " "))
            launch.append(f"Launches `{command}` on the developer's machine.")
        elif other_atom.action == "remote_server":
            host = other_atom.egress_hosts[0] if other_atom.egress_hosts else "a remote host"
            launch.append(f"Connects the agent to `{host}`.")
    if not launch and atom.action == "project_setting":
        launch.append("Registers a server the agent can call tools on.")
    allows = launch[:2]
    if credentials:
        allows.append(
            "Hands it credentials from: " + ", ".join(f"`{k}`" for k in sorted(credentials))
        )
    severity = Severity.HIGH if credentials or atom.action == "remote_server" else Severity.MEDIUM
    return CheckFinding(
        check="config-guard",
        rule_id="CG005",
        severity=severity,
        title=f"New MCP server `{name}`",
        path=atom.path,
        line=_line_of(head.get(atom.path, ""), f'"{name}"'),
        allows=tuple(allows),
        fix=(
            "Pin the package to an exact version, pass only the credentials it needs, "
            "and list the tools you use rather than all of them."
        ),
    )


# --- instruction text ----------------------------------------------------------------------


def _instruction_findings(
    base: Mapping[str, str], head: Mapping[str, str]
) -> Iterable[CheckFinding]:
    for path, text in head.items():
        if not _is_instruction(path):
            continue
        before = base.get(path, "").splitlines()
        after = text.splitlines()
        added: dict[int, str] = {}
        matcher = difflib.SequenceMatcher(a=before, b=after, autojunk=False)
        for tag, _i1, _i2, j1, j2 in matcher.get_opcodes():
            if tag in {"insert", "replace"}:
                for index in range(j1, j2):
                    added[index + 1] = after[index]
        for line_no, line in added.items():
            if _SKIP_CHECK_RE.search(line):
                yield CheckFinding(
                    check="config-guard",
                    rule_id="CG006",
                    severity=Severity.HIGH,
                    title="New instruction tells agents to skip a check",
                    path=path,
                    line=line_no,
                    allows=(f"Agents reading `{path}` are told: “{_short(line.strip(), 160)}”",),
                    fix=(
                        "Remove the line, or narrow it to what may be skipped and say which "
                        "check still runs (for example: CI still runs the full suite)."
                    ),
                )


# --- skill frontmatter and Codex rule files -------------------------------------------------


def _rule_file_findings(
    base: Mapping[str, str], head: Mapping[str, str], notes: list[str]
) -> Iterable[tuple[tuple[str, ...], CheckFinding]]:
    for path, text in head.items():
        if _SKILL_RE.search(path):
            kind = "skill allowed-tools"
            before = _frontmatter_rules(base.get(path, ""), path, kind)
            after = _frontmatter_rules(text, path, kind)
        elif _CODEX_RULES_RE.search(path):
            try:
                before = _codex_rules(base.get(path, ""), path)
                after = _codex_rules(text, path)
            except RulesParseError:
                notes.append(f"`{path}` could not be parsed as Codex rules; it was not expanded.")
                continue
        else:
            continue
        known = {rule.raw for rule in before if rule.decision == "allow"}
        for rule in after:
            if rule.decision != "allow" or rule.raw in known:
                continue
            finding = _allow_finding(rule, path, head)
            if finding is not None and _SKILL_RE.search(path):
                finding = _while_skill_runs(finding, path)
            if finding is not None:
                yield ("allow", path, rule.raw), finding


def _frontmatter_rules(text: str, path: str, kind: str) -> list[Rule]:
    if not text.startswith("---"):
        return []
    parts = text.split("---", 2)
    if len(parts) < 3:
        return []
    try:
        data = yaml.safe_load(parts[1])
    except yaml.YAMLError:
        return []
    if not isinstance(data, Mapping):
        return []
    value = data.get("allowed-tools", data.get("tools"))
    return parse_allowed_tools(value, Source("claude", kind, path, path)) if value else []


def _codex_rules(text: str, path: str) -> list[Rule]:
    return parse_rules_text(text, _source(path, "codex rules")) if text.strip() else []


def _while_skill_runs(finding: CheckFinding, path: str) -> CheckFinding:
    name = PurePosixPath(path).stem
    if name.upper() == "SKILL":
        name = PurePosixPath(path).parent.name
    return replace(finding, title=f"{finding.title} while `{name}` runs")


# --- other engine findings -----------------------------------------------------------------


def _from_engine(finding: Finding, head: Mapping[str, str]) -> CheckFinding | None:
    if finding.acknowledged:
        return None
    paths = finding.paths()
    path = paths[0] if paths else ""
    allows = [finding.summary]
    allows.extend(item for item in finding.evidence[:1] if item and item != finding.summary)
    value = finding.changes[0].atom.value if finding.changes else ""
    return CheckFinding(
        check="config-guard",
        rule_id=finding.rule_id,
        severity=finding.severity,
        title=finding.title,
        path=path,
        line=_line_of(head.get(path, ""), value) if value else None,
        allows=tuple(_short(item, 200) for item in allows),
        fix=finding.reviewer_decision,
    )


# --- helpers -------------------------------------------------------------------------------


def _line_of(text: str, needle: str) -> int | None:
    if not needle or not text:
        return None
    # An exact quoted value first, so `Bash` does not land on `"Bash(npm test)"`.
    lines = text.splitlines()
    for candidate in (json.dumps(needle), f"'{needle}'", needle, json.dumps(needle)[1:-1]):
        for number, line in enumerate(lines, start=1):
            if candidate in line:
                return number
    return None


def _short(text: str, limit: int = 120) -> str:
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 1] + "…"
