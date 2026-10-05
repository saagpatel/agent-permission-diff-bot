"""Static project startup surfaces; never execute commands or resolve external paths."""

from __future__ import annotations

import ast
import hashlib
import json
import re
import shlex
import tomllib
from collections.abc import Mapping
from pathlib import PurePosixPath

from agent_permission_diff_bot.model import Finding, PermissionAtom, PermissionChange, Severity

PROJECT_CONFIGS = {
    ".claude/settings.json": "claude",
    ".claude/settings.local.json": "claude",
    ".vscode/tasks.json": "vscode",
    ".vscode/settings.json": "vscode",
    ".codex/config.toml": "codex",
    ".codex/hooks.json": "codex",
    ".gemini/settings.json": "gemini",
    ".cursor/hooks.json": "cursor",
}
PAYLOAD_PATTERNS = {
    "download_pipe_execute": re.compile(r"\b(?:curl|wget)\b[^\n]*\|\s*(?:sh|bash|node)\b", re.I),
    "base64_decode": re.compile(r"\bbase64\s+(?:-d\b|--decode\b)", re.I),
    "eval": re.compile(r"\beval\b"),
    "node_inline": re.compile(r"\bnode\s+(?:-e\b|--eval\b)"),
    "python_inline_network": re.compile(
        r"\bpython(?:3)?\s+-c\b[^\n]*(?:https?://|urllib|requests|socket)", re.I
    ),
    "credential_reference": re.compile(r"(?:~/)?\.(?:ssh|aws)\b|\.npmrc\b|\bGITHUB_TOKEN\b"),
    "hidden_unicode": re.compile("[\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff]"),
}
# JSONC comments/trailing commas are accepted for editor configuration. Quoted strings
# take precedence so URLs and command strings are left intact.
JSONC_TOKEN = re.compile(r'"(?:\\.|[^"\\])*"|//[^\n]*|/\*[\s\S]*?\*/|,\s*(?=[}\]])')
JS_TOKEN = re.compile(
    r'"(?:\\.|[^"\\])*"|'
    r"'(?:\\.|[^'\\])*'|"
    r"`(?:\\.|[^`\\])*`|"
    r"//[^\n]*|/\*[\s\S]*?(?:\*/|$)|"
    r"[A-Za-z_$][\w$]*|\S"
)


def load_project_config(path: str, text: str) -> Mapping:
    try:
        if path.endswith(".toml"):
            data = tomllib.loads(text)
        else:
            cleaned = JSONC_TOKEN.sub(
                lambda match: match[0] if match[0].startswith('"') else " ", text
            )
            cleaned = JSONC_TOKEN.sub(
                lambda match: match[0] if match[0].startswith('"') else " ", cleaned
            )
            data = json.loads(cleaned)
    except (ValueError, tomllib.TOMLDecodeError):
        return {}
    return data if isinstance(data, Mapping) else {}


def _value(value: object) -> str:
    return value if isinstance(value, str) else json.dumps(value, sort_keys=True)


def _atom(
    path: str, action: str, resource: str, value: object, *, trigger: str = "", scope: str = "repo"
) -> PermissionAtom:
    surface = PROJECT_CONFIGS.get(path, "instructions")
    rendered = _value(value)
    return PermissionAtom(
        surface=surface,
        actor=f"{surface}:{path}:{trigger or resource}",
        action=action,
        verb="execute" if action in {"auto_hook", "folder_open_task"} else "configure",
        resource=resource,
        value=rendered,
        path=path,
        trigger=trigger,
        scope=scope,
        evidence=f"{path}: {trigger + ' ' if trigger else ''}{resource}: {rendered}",
    )


def _hooks(path: str, hooks: object) -> list[PermissionAtom]:
    if not isinstance(hooks, Mapping):
        return []
    atoms: list[PermissionAtom] = []

    def walk(event: str, item: object, context: dict) -> None:
        if isinstance(item, list):
            for child in item:
                walk(event, child, context)
        elif isinstance(item, Mapping):
            metadata = {k: v for k, v in item.items() if k not in {"hooks", "command"}}
            inherited = {**context, **metadata}
            command = item.get("command")
            if isinstance(command, (str, list)):
                # argv-style hook commands are rendered as shell-quoted text, never run.
                rendered = shlex.join(map(str, command)) if isinstance(command, list) else command
                # Preserve metadata changes without copying arbitrary hook env/secret
                # values into reports. Known execution selectors stay inspectable.
                scope = {
                    "metadata_sha256": hashlib.sha256(_value(inherited).encode()).hexdigest(),
                    **{
                        key: inherited[key]
                        for key in ("matcher", "type", "timeout", "async", "once")
                        if key in inherited
                    },
                }
                atoms.append(
                    _atom(
                        path,
                        "auto_hook",
                        "command",
                        rendered,
                        trigger=event,
                        scope=_value(scope),
                    )
                )
            if "hooks" in item:
                walk(event, item["hooks"], inherited)

    for event, entries in hooks.items():
        walk(str(event), entries, {})
    return atoms


def extract_project_atoms(path: str, text: str) -> list[PermissionAtom]:
    data = load_project_config(path, text)
    atoms = _hooks(path, data.get("hooks"))
    permissions = data.get("permissions")
    if isinstance(permissions, Mapping):
        for key in ("allow", "deny"):
            entries = permissions.get(key, [])
            if isinstance(entries, list):
                atoms.extend(_atom(path, "permission_rule", key, entry) for entry in entries)
        if "defaultMode" in permissions:
            atoms.append(_atom(path, "permission_mode", "defaultMode", permissions["defaultMode"]))
    for key in ("sandbox_mode", "approval_policy"):
        if key in data:
            atoms.append(_atom(path, "permission_mode", key, data[key]))
    for key in ("enableAllProjectMcpServers", "enabledMcpjsonServers", "apiKeyHelper"):
        if key in data:
            values = data[key] if isinstance(data[key], list) else [data[key]]
            atoms.extend(_atom(path, "project_setting", key, entry) for entry in values)
    for key in ("enabledPlugins", "extraKnownMarketplaces"):
        entries = data.get(key)
        if isinstance(entries, Mapping):
            atoms.extend(_atom(path, "plugin", str(name), value) for name, value in entries.items())
    servers = data.get("mcpServers", data.get("mcp_servers"))
    if isinstance(servers, Mapping):
        atoms.extend(_atom(path, "project_setting", "mcpServers", str(name)) for name in servers)
    env = data.get("env")
    if isinstance(env, Mapping):
        # Record environment key additions without copying possible secret values.
        atoms.extend(_atom(path, "environment", "env", str(key)) for key in env)
    if path == ".vscode/tasks.json":
        tasks = data.get("tasks", [])
        if isinstance(tasks, list):
            for task in tasks:
                if not isinstance(task, Mapping):
                    continue
                options = task.get("runOptions")
                if isinstance(options, Mapping) and options.get("runOn") == "folderOpen":
                    atoms.append(
                        _atom(path, "folder_open_task", "task", task, trigger="folderOpen")
                    )
    if path == ".vscode/settings.json":
        for key, value in data.items():
            if key == "task.allowAutomaticTasks" or str(key).startswith(
                (
                    "terminal.integrated.profiles.",
                    "terminal.integrated.automationProfile.",
                    "terminal.integrated.defaultProfile.",
                    "terminal.integrated.shell.",
                    "terminal.integrated.shellArgs.",
                )
            ):
                atoms.append(_atom(path, "editor_execution", str(key), value))
    return atoms


def extract_payload_atoms(path: str, text: str) -> list[PermissionAtom]:
    atoms = []
    for name, pattern in PAYLOAD_PATTERNS.items():
        matches = pattern.findall(text)
        if matches:
            # Escape invisible characters so reviewers see the signal in every renderer.
            values = sorted({match.encode("unicode_escape").decode() for match in matches})
            atoms.append(_atom(path, "payload_smell", name, values))
    return atoms


def _inline_file_loads(name: str, code: str) -> set[str]:
    """Recognize literal executable loads; parse syntax without evaluating inline code."""
    if name in {"node", "nodejs", "bun", "deno"}:
        tokens = [
            match[0] for match in JS_TOKEN.finditer(code) if not match[0].startswith(("//", "/*"))
        ]
        paths = set()
        for index in range(len(tokens) - 3):
            if (
                tokens[index] not in {"require", "import"}
                or tokens[index + 1] != "("
                or tokens[index + 2][0] not in {"'", '"'}
                or tokens[index + 3] not in {")", ","}
                or (index > 0 and tokens[index - 1] == ".")
            ):
                continue
            try:
                # The lexer admitted a single quoted literal, never an expression.
                target = ast.literal_eval(tokens[index + 2])
            except (ValueError, SyntaxError):
                continue
            if isinstance(target, str) and PurePosixPath(target).suffix in {
                ".js",
                ".mjs",
                ".cjs",
                ".ts",
                ".tsx",
            }:
                paths.add(target)
        return paths
    if not re.fullmatch(r"python(?:\d+(?:\.\d+)?)?", name):
        return set()
    try:
        tree = ast.parse(code)
    except (SyntaxError, ValueError):
        return set()
    paths = set()
    for call in ast.walk(tree):
        if not isinstance(call, ast.Call) or not call.args:
            continue
        candidates = []
        if isinstance(call.func, ast.Name) and call.func.id == "exec":
            candidates = [
                child.args[0]
                for child in ast.walk(call.args[0])
                if isinstance(child, ast.Call)
                and isinstance(child.func, ast.Name)
                and child.func.id == "open"
                and child.args
            ]
        elif (
            isinstance(call.func, ast.Attribute)
            and call.func.attr == "run_path"
            and isinstance(call.func.value, ast.Name)
            and call.func.value.id == "runpy"
        ):
            candidates = [call.args[0]]
        for argument in candidates:
            if isinstance(argument, ast.Constant) and isinstance(argument.value, str):
                paths.add(argument.value)
    return paths


def referenced_paths(command: str, *, _depth: int = 0) -> set[str]:
    """Recognize literal repo-relative paths only; no shell expansion or filesystem reads."""
    for root in (
        "${CLAUDE_PROJECT_DIR}",
        "$CLAUDE_PROJECT_DIR",
        "${workspaceFolder}",
        "${GEMINI_PROJECT_DIR}",
        "$GEMINI_PROJECT_DIR",
        "${PWD}",
        "$PWD",
    ):
        command = command.replace(root + "/", "./")
    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars=True)
        lexer.whitespace_split = True
        lexer.commenters = ""
        tokens = list(lexer)
    except ValueError:
        return set()
    paths: set[str] = set()

    def add_literal(token: str) -> None:
        candidate = PurePosixPath(token)
        if (
            any(ord(char) < 32 for char in token)
            or not token
            or token.startswith(("-", "~"))
            or candidate.is_absolute()
            or ".." in candidate.parts
            or any(char in token for char in "$|;&<>*?\n")
            or ":" in token
            or any(part in {".ssh", ".aws"} for part in candidate.parts)
            or candidate.name in {".npmrc", ".netrc", ".pypirc", ".env"}
            or candidate.name.startswith(".env.")
        ):
            return
        if "/" in token or candidate.suffix:
            paths.add(candidate.as_posix())

    segments: list[list[str]] = [[]]
    for token in tokens:
        if token in {";", "&&", "||", "|", "&", "(", ")"}:
            segments.append([])
        else:
            segments[-1].append(token)
    interpreters = {
        "node",
        "nodejs",
        "bun",
        "deno",
        "tsx",
        "ts-node",
        "ruby",
        "perl",
        "sh",
        "bash",
        "zsh",
        "dash",
        "pwsh",
        "powershell",
    }
    for segment in segments:
        # Recognize execution positions, rather than treating formatter/read operands
        # as executable payloads. Unsupported launchers remain unresolved static evidence.
        while segment and ("=" in segment[0] or segment[0] in {"env", "exec", "command", "nohup"}):
            segment = segment[1:]
        if len(segment) >= 2 and segment[:2] in (["uv", "run"], ["poetry", "run"]):
            segment = segment[2:]
        if not segment:
            continue
        executable, *arguments = segment
        name = PurePosixPath(executable).name
        if name not in interpreters and not re.fullmatch(r"python(?:\d+(?:\.\d+)?)?", name):
            # A direct repo path is a possible executable; a plain PATH tool isn't.
            if "/" in executable:
                add_literal(executable)
            continue
        if name in {"bun", "deno"} and arguments[:1] == ["run"]:
            arguments = arguments[1:]
        index = 0
        while index < len(arguments):
            token = arguments[index]
            if token in {"-c", "-lc", "-ic"} and name in {"sh", "bash", "zsh", "dash"}:
                if _depth < 3 and index + 1 < len(arguments):
                    paths.update(referenced_paths(arguments[index + 1], _depth=_depth + 1))
                break
            if token in {"-e", "--eval", "-c"}:
                if index + 1 < len(arguments):
                    for target in _inline_file_loads(name, arguments[index + 1]):
                        add_literal(target)
                break
            if token == "-m":
                break  # Module resolution is runtime-dependent.
            if token in {"-r", "--require", "--import", "--loader"} and name in {"node", "nodejs"}:
                if index + 1 < len(arguments):
                    add_literal(arguments[index + 1])
                index += 2
                continue
            if token.lower() in {"-executionpolicy", "--conditions"}:
                index += 2
                continue
            if token.startswith("-"):
                index += 1
                continue
            add_literal(token)
            break
    return paths


def snapshot_hook_references(files: dict[str, str]) -> set[str]:
    return {
        target
        for path, text in files.items()
        if path in PROJECT_CONFIGS
        for atom in extract_project_atoms(path, text)
        if atom.action == "auto_hook"
        for target in referenced_paths(atom.value)
    }


MODE_RANKS = {
    "defaultMode": {
        "plan": 0,
        "dontAsk": 0,
        "default": 1,
        "acceptEdits": 2,
        "bypassPermissions": 4,
    },
    "sandbox_mode": {"read-only": 0, "workspace-write": 1, "danger-full-access": 2},
    "approval_policy": {"untrusted": 0, "on-request": 1, "on-failure": 2, "never": 3},
}


def _covers_rule(broad: str, narrow: str) -> bool:
    """Only prove containment for an exact rule or a whole-tool wildcard."""
    if broad == narrow or broad == "*":
        return True
    tool = narrow.split("(", 1)[0]
    return broad in {tool, f"{tool}(*)"}


def persistence_findings(changes: list[PermissionChange]) -> list[Finding]:
    findings: list[Finding] = []
    for change in changes:
        atom = change.atom
        added = change.kind == "added"
        severity = Severity.MEDIUM
        title = "Project execution or permission setting changed"
        rule = "APD008"
        if atom.action == "auto_hook":
            rule, title = "APD007", "Agent lifecycle hook changed"
            severity = (
                Severity.HIGH
                if added and atom.trigger.lower() in {"sessionstart", "session_start"}
                else Severity.MEDIUM
                if added
                else Severity.LOW
            )
        elif atom.action == "permission_rule":
            widening = (added and atom.resource == "allow") or (
                not added and atom.resource == "deny"
            )
            if widening:
                counterparts = [
                    other.atom.value
                    for other in changes
                    if other.kind == ("removed" if added else "added")
                    and other.atom.path == atom.path
                    and other.atom.action == atom.action
                    and other.atom.resource == atom.resource
                ]
                # Replacing a whole-tool allow with a narrower rule, or a deny with
                # a broader deny, does not widen permissions. Unknown patterns stay high.
                widening = not any(_covers_rule(value, atom.value) for value in counterparts)
            severity = Severity.HIGH if widening else Severity.LOW
            title = "Agent permission rule changed"
        elif atom.action == "permission_mode":
            ranks = MODE_RANKS[atom.resource]
            previous = [
                other.atom.value
                for other in changes
                if other.kind == "removed"
                and other.atom.path == atom.path
                and other.atom.resource == atom.resource
                and other.atom.action == atom.action
            ]
            if added:
                old_rank = ranks.get(previous[0]) if previous else None
                new_rank = ranks.get(atom.value)
                if new_rank is not None:
                    widening = new_rank > old_rank if old_rank is not None else new_rank > 1
                    severity = Severity.HIGH if widening else Severity.LOW
                    if widening and atom.value in {"bypassPermissions", "danger-full-access"}:
                        severity = Severity.CRITICAL
            else:
                severity = (
                    Severity.LOW
                    if previous
                    and any(
                        other.kind == "added"
                        and other.atom.path == atom.path
                        and other.atom.resource == atom.resource
                        and other.atom.action == atom.action
                        for other in changes
                    )
                    else Severity.MEDIUM
                )
            title = "Agent sandbox or approval mode changed"
        elif atom.action == "folder_open_task":
            rule, title = "APD009", "VS Code folderOpen task changed"
            severity = Severity.CRITICAL if added else Severity.LOW
        elif atom.action in {"project_setting", "editor_execution", "plugin", "environment"}:
            if not added or atom.value in {"false", "off", "null"}:
                severity = Severity.LOW
            else:
                severity = Severity.HIGH if atom.action != "environment" else Severity.MEDIUM
        elif atom.action == "always_apply_rule":
            rule, title = "APD010", "Always-applied Cursor rule changed"
            severity = Severity.HIGH if added else Severity.LOW
        elif atom.action == "payload_smell":
            if not added:
                continue
            rule, title = "APD011", "Suspicious project startup payload"
            severity = Severity.HIGH
        elif atom.action == "hook_executable":
            rule, title = "APD012", "New executable referenced by an auto-run hook"
            severity = Severity.HIGH
        else:
            continue
        findings.append(
            Finding(
                rule_id=rule,
                title=title,
                severity=severity,
                summary=f"{change.kind.capitalize()} {atom.resource} in `{atom.path}`.",
                evidence=[atom.evidence],
                changes=[change],
                reviewer_decision="Confirm this static execution or permission change is intended.",
            )
        )

    additions = [change for change in changes if change.kind == "added"]
    hooks = [c for c in additions if c.atom.action == "auto_hook"]
    executables = [c for c in additions if c.atom.action == "hook_executable"]
    claude = [c for c in hooks if c.atom.surface == "claude"]
    tasks = [c for c in additions if c.atom.action == "folder_open_task"]
    if (hooks and executables) or (claude and tasks):
        involved = [*hooks, *executables, *tasks]
        findings.append(
            Finding(
                rule_id="APD105",
                title="Worm-shaped persistence",
                severity=Severity.CRITICAL,
                summary=(
                    "Added lifecycle hooks and payloads or folderOpen tasks resemble the "
                    "August 2026 keyv Mini Shai-Hulud persistence pattern; static evidence "
                    "does not establish infection."
                ),
                evidence=[c.atom.evidence for c in involved],
                changes=involved,
                reviewer_decision=(
                    "Review the startup commands and payload together before trusting them."
                ),
            )
        )
    return findings
