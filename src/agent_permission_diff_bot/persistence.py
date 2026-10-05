"""Static project startup surfaces; never execute commands or resolve external paths."""

from __future__ import annotations

import ast
import hashlib
import json
import posixpath
import re
import shlex
import tomllib
from collections.abc import Mapping
from dataclasses import replace
from itertools import pairwise
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
_EMOJI = (
    "\u00a9\u00ae\u203c\u2049\u2122\u2139\u2194-\u2199\u21a9\u21aa\u231a-\u23ff"
    "\u24c2\u25aa-\u27bf\u2934\u2935\u2b05-\u2b55\u3030\u303d\u3297\u3299"
    "\U0001f000-\U0001faff0-9#*"
)
PAYLOAD_PATTERNS = {
    "download_pipe_execute": re.compile(r"\b(?:curl|wget)\b[^\n|]*\|\s*(?:sh|bash|node)\b", re.I),
    "base64_decode": re.compile(r"\bbase64\s+(?:-d\b|--decode\b)", re.I),
    "eval": re.compile(r"\beval\b"),
    "node_inline": re.compile(r"\bnode\s+(?:-e\b|--eval\b)"),
    "python_inline_network": re.compile(
        r"\bpython(?:3)?\s+-c\b[^\n]*(?:https?://|urllib|requests|socket)", re.I
    ),
    "credential_reference": re.compile(r"(?:~/)?\.(?:ssh|aws)\b|\.npmrc\b|\bGITHUB_TOKEN\b"),
    # VS16 (U+FE0F) and ZWJ (U+200D) are ordinary parts of emoji sequences such as
    # "\u26a0\ufe0f" or family emoji; flag them only when they are not attached to an emoji.
    "hidden_unicode": re.compile(
        "[\u00ad\u034f\u180e\u200b\u200c\u200e\u200f\u202a-\u202e\u2060-\u2069"
        "\ufeff\ufe00-\ufe0e\U000e0000-\U000e007f\U000e0100-\U000e01ef]"
        f"|(?<![{_EMOJI}])\ufe0f"
        f"|(?<![{_EMOJI}\ufe0f])\u200d"
        f"|\u200d(?![{_EMOJI}])"
    ),
}
MAX_CONFIG_BYTES = 2 * 1024 * 1024
MAX_INLINE_BYTES = 64 * 1024
FOLDER_OPEN_RAW = re.compile(r'"runOn"\s*:\s*"folderopen"', re.I)
JS_TOKEN = re.compile(
    r'"(?:\\.|[^"\\])*"|'
    r"'(?:\\.|[^'\\])*'|"
    r"`(?:\\.|[^`\\])*`|"
    r"//[^\n]*|/\*[\s\S]*?(?:\*/|$)|"
    r"[A-Za-z_$][\w$]*|\S"
)


class ProjectConfig(dict):
    """Parsed mapping plus a visible failure, without reserving user JSON keys."""

    def __init__(self, data: Mapping | None = None, *, error: str = "") -> None:
        super().__init__(data or {})
        self.error = error


ConfigCache = dict[tuple[str, str], ProjectConfig]


def project_config_kind(path: str) -> str | None:
    normalized = path.replace("\\", "/").lower().removeprefix("./")
    for config, kind in PROJECT_CONFIGS.items():
        if normalized == config or normalized.endswith("/" + config):
            return kind
    parts = PurePosixPath(normalized).parts
    if ".codex" in parts and normalized.endswith(".config.toml"):
        return "codex"
    if normalized.endswith(".code-workspace"):
        return "vscode"
    return None


def _strip_jsonc(text: str) -> str:
    """One linear lexical pass; preserve strings, whitespace and line numbers."""
    output: list[str] = []
    index = 0
    quoted = escaped = False
    comma: int | None = None
    while index < len(text):
        char = text[index]
        if quoted:
            output.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
            index += 1
            continue
        if text.startswith("//", index):
            end = text.find("\n", index + 2)
            end = len(text) if end < 0 else end
            output.append(" " * (end - index))
            index = end
            continue
        if text.startswith("/*", index):
            end = text.find("*/", index + 2)
            if end < 0:
                raise ValueError("unterminated JSONC comment")
            end += 2
            output.extend("\n" if c == "\n" else " " for c in text[index:end])
            index = end
            continue
        if not char.isspace():
            if char in "}]" and comma is not None:
                output[comma] = " "
            comma = len(output) if char == "," else None
            quoted = char == '"'
        output.append(char)
        index += 1
    return "".join(output)


def load_project_config(path: str, text: str, cache: ConfigCache | None = None) -> ProjectConfig:
    key = (path, text)
    if cache is not None and key in cache:
        return cache[key]
    result = _parse_project_config(path, text)
    if cache is not None:
        cache[key] = result
    return result


def _parse_project_config(path: str, text: str) -> ProjectConfig:
    if len(text.encode("utf-8", errors="surrogateescape")) > MAX_CONFIG_BYTES:
        return ProjectConfig(error="startup config exceeds 2 MB size limit")
    text = text.removeprefix("\ufeff")
    try:
        if path.lower().endswith(".toml"):
            data = tomllib.loads(text)
        else:
            try:
                data = json.loads(text)
            except ValueError:
                data = json.loads(_strip_jsonc(text))
    except (ValueError, MemoryError, RecursionError):
        return ProjectConfig(error="unparseable startup config")
    if not isinstance(data, Mapping):
        return ProjectConfig(error="startup config must be an object")
    return ProjectConfig(data)


def _value(value: object) -> str:
    return value if isinstance(value, str) else json.dumps(value, sort_keys=True)


def _atom(
    path: str, action: str, resource: str, value: object, *, trigger: str = "", scope: str = "repo"
) -> PermissionAtom:
    surface = project_config_kind(path) or "instructions"
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

    pending: list[tuple[str, object, dict[str, object]]] = [
        (str(event), entries, {}) for event, entries in hooks.items()
    ]
    while pending:
        event, item, context = pending.pop()
        if isinstance(item, list):
            pending.extend((event, child, context) for child in item)
        elif isinstance(item, Mapping):
            metadata = {k: v for k, v in item.items() if k not in {"hooks", "command"}}
            inherited = {**context, **metadata}
            command = item.get("command")
            if isinstance(command, (str, list)):
                rendered = shlex.join(map(str, command)) if isinstance(command, list) else command
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
                        path, "auto_hook", "command", rendered, trigger=event, scope=_value(scope)
                    )
                )
            if "hooks" in item:
                pending.append((event, item["hooks"], inherited))
    return atoms


def project_config_sections(path: str, data: Mapping) -> list[tuple[str, Mapping]]:
    sections = [("", data)]
    profiles = data.get("profiles")
    if project_config_kind(path) == "codex" and isinstance(profiles, Mapping):
        sections.extend(
            (f"profiles.{name}", profile)
            for name, profile in profiles.items()
            if isinstance(profile, Mapping)
        )
    return sections


def extract_project_atoms(
    path: str, text: str, cache: ConfigCache | None = None
) -> list[PermissionAtom]:
    data = load_project_config(path, text, cache)
    if data.error:
        digest = hashlib.sha256(text.encode("utf-8", errors="surrogateescape")).hexdigest()
        atoms = [_atom(path, "unparseable_config", "startup config", data.error, scope=digest)]
        if is_task_config(path) and FOLDER_OPEN_RAW.search(text[:MAX_CONFIG_BYTES]):
            atoms.append(
                _atom(
                    path,
                    "folder_open_task",
                    "unparsed task",
                    "raw folderOpen marker",
                    trigger="folderOpen",
                    scope=digest,
                )
            )
        return atoms
    atoms = []
    for section, values in project_config_sections(path, data):
        for atom in _project_section_atoms(path, values):
            atoms.append(replace(atom, actor=f"{atom.actor}:{section}") if section else atom)
    return atoms


def is_task_config(path: str) -> bool:
    lowered = path.lower()
    return lowered.endswith((".vscode/tasks.json", ".code-workspace"))


def config_tasks(path: str, data: Mapping) -> list:
    tasks = data.get("tasks", [])
    if path.lower().endswith(".code-workspace") and isinstance(tasks, Mapping):
        tasks = tasks.get("tasks", [])
    return tasks if isinstance(tasks, list) else []


def task_command(task: Mapping) -> str:
    command = task.get("command", "")
    if not isinstance(command, str):
        return ""
    args = task.get("args", [])
    if isinstance(args, list):
        # Shell task commands may already contain executable and options; only quote args.
        command += " " + shlex.join(str(arg) for arg in args if isinstance(arg, (str, int)))
    return command


def _project_section_atoms(path: str, data: Mapping) -> list[PermissionAtom]:
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
    for key in ("enableAllProjectMcpServers", "enabledMcpjsonServers"):
        if key in data:
            values = data[key] if isinstance(data[key], list) else [data[key]]
            atoms.extend(_atom(path, "project_setting", key, entry) for entry in values)
    if project_config_kind(path) == "claude":
        status = data.get("statusLine")
        if isinstance(status, Mapping) and status.get("type") == "command":
            command = status.get("command")
            if isinstance(command, str):
                atoms.append(_atom(path, "auto_hook", "command", command, trigger="statusLine"))
        for key in ("apiKeyHelper", "awsAuthRefresh", "awsCredentialExport", "otelHeadersHelper"):
            command = data.get(key)
            if isinstance(command, str):
                atoms.append(_atom(path, "auto_hook", "command", command, trigger=key))
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
    if is_task_config(path):
        for task in config_tasks(path, data):
            if not isinstance(task, Mapping):
                continue
            options = task.get("runOptions")
            if isinstance(options, Mapping) and str(options.get("runOn")).lower() == "folderopen":
                atoms.append(_atom(path, "folder_open_task", "task", task, trigger="folderOpen"))
    if path.lower().endswith(".vscode/settings.json"):
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


def project_command_strings(path: str, data: Mapping, atoms: list[PermissionAtom]) -> list[str]:
    commands = [atom.value for atom in atoms if atom.action == "auto_hook"]
    for _, section in project_config_sections(path, data):
        commands.extend(
            task_command(task) for task in config_tasks(path, section) if isinstance(task, Mapping)
        )
    return commands


def extract_payload_atoms(
    path: str, text: str, *, hidden_only: bool = False
) -> list[PermissionAtom]:
    atoms = []
    text = text.removeprefix("\ufeff")
    for name, pattern in PAYLOAD_PATTERNS.items():
        if hidden_only and name != "hidden_unicode":
            continue
        if name == "download_pipe_execute":
            # Do not retry a greedy line suffix at every curl/wget token: repeated
            # download words without a pipe otherwise make the scan quadratic.
            matches = []
            for line in text.splitlines():
                segments = line.split("|")
                for before, after in pairwise(segments):
                    if re.search(r"\b(?:curl|wget)\b", before, re.I) and re.match(
                        r"\s*(?:sh|bash|node)\b", after, re.I
                    ):
                        matches.append(before + "|" + after)
        else:
            matches = pattern.findall(text)
        if matches:
            # Escape invisible characters so reviewers see the signal in every renderer.
            values = sorted({match.encode("unicode_escape").decode() for match in matches})
            atoms.append(_atom(path, "payload_smell", name, values))
    return atoms


def _inline_file_loads(name: str, code: str) -> set[str]:
    try:
        if len(code.encode("utf-8", errors="surrogatepass")) > MAX_INLINE_BYTES:
            return set()
        return _parse_inline_file_loads(name, code)
    except (MemoryError, RecursionError):
        return set()


def _parse_inline_file_loads(name: str, code: str) -> set[str]:
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


# Value-taking interpreter options. Preload options additionally execute their value.
NODE_VALUE_OPTIONS = {
    "--env-file",
    "--env-file-if-exists",
    "--stack-size",
    "--stack_size",
    "-r",
    "--require",
    "--import",
    "--loader",
    "--experimental-loader",
    "--conditions",
    "--inspect-port",
    "--input-type",
    "--title",
    "--icu-data-dir",
    "--openssl-config",
    "--redirect-warnings",
    "--diagnostic-dir",
    "--max-old-space-size",
    "--max_old_space_size",
    "-C",
    "--dns-result-order",
    "--unhandled-rejections",
    "--max-http-header-size",
    "--cpu-prof-dir",
    "--cpu-prof-name",
    "--cpu-prof-interval",
    "--heap-prof-dir",
    "--heap-prof-name",
    "--heap-prof-interval",
    "--heapsnapshot-near-heap-limit",
    "--heapsnapshot-signal",
    "--inspect-publish-uid",
    "--debug-port",
    "--disable-proto",
    "--disable-warning",
    "--max-old-space-size-percentage",
    "--network-family-autoselection-attempt-timeout",
    "--report-directory",
    "--report-dir",
    "--report-filename",
    "--report-signal",
    "--secure-heap",
    "--secure-heap-min",
    "--tls-cipher-list",
    "--tls-keylog",
    "--trace-event-categories",
    "--trace-event-file-pattern",
    "--trace-require-module",
    "--use-largepages",
    "--v8-pool-size",
    "--watch-path",
    "--watch-kill-signal",
}
NODE_LOAD_OPTIONS = {"-r", "--require", "--import", "--loader", "--experimental-loader"}
PYTHON_VALUE_OPTIONS = {"-X", "-W", "--check-hash-based-pycs"}
ROOT_VARIABLES = (
    "${CLAUDE_PROJECT_DIR}",
    "$CLAUDE_PROJECT_DIR",
    "${workspaceFolder}",
    "${GEMINI_PROJECT_DIR}",
    "$GEMINI_PROJECT_DIR",
    "${PWD}",
    "$PWD",
)
ROOT_MARKER = "/__apd_repo_root__"


def referenced_paths(command: str, *, _depth: int = 0, _cwd: str = "") -> set[str]:
    """Resolve clear execution positions lexically; never expand the shell or read files."""
    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars=True)
        lexer.whitespace_split = True
        lexer.commenters = ""
        tokens = list(lexer)
    except ValueError:
        return set()
    # Tokenize first: shell quotes may surround only the variable part of a path.
    tokens = [
        next(
            (
                ROOT_MARKER + token[len(root) :]
                for root in ROOT_VARIABLES
                if token == root or token.startswith(root + "/")
            ),
            token,
        )
        for token in tokens
    ]
    paths: set[str] = set()
    cwd: str | None = _cwd

    def literal(token: str) -> str | None:
        anchored = token == ROOT_MARKER or token.startswith(ROOT_MARKER + "/")
        if anchored:
            token = token[len(ROOT_MARKER) :].lstrip("/") or "."
        if (
            not token
            or token.startswith(("-", "~"))
            or any(ord(char) < 32 for char in token)
            or any(char in token for char in "$|;&<>*?\n")
            or ":" in token
            or PurePosixPath(token).is_absolute()
            or (cwd is None and not anchored)
        ):
            return None
        normalized = posixpath.normpath(posixpath.join("" if anchored else cwd or "", token))
        candidate = PurePosixPath(normalized)
        if (
            normalized == ".."
            or normalized.startswith("../")
            or any(part.lower() in {".git", ".ssh", ".aws"} for part in candidate.parts)
            or candidate.name in {".npmrc", ".netrc", ".pypirc", ".env"}
            or candidate.name.startswith(".env.")
        ):
            return None
        return normalized

    def add_literal(token: str) -> None:
        target = literal(token)
        if target and ("/" in token or PurePosixPath(token).suffix):
            paths.add(target)

    segments: list[tuple[list[str], str]] = []
    current: list[str] = []
    for token in tokens:
        if token in {";", "&&", "||", "|", "&", "(", ")"}:
            segments.append((current, token))
            current = []
        else:
            current.append(token)
    segments.append((current, ""))
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
    for segment, connector in segments:
        while segment and ("=" in segment[0] or segment[0] in {"env", "exec", "command", "nohup"}):
            segment = segment[1:]
        if len(segment) >= 2 and segment[:2] in (["uv", "run"], ["poetry", "run"]):
            segment = segment[2:]
        if (
            segment[:1] == ["timeout"]
            and len(segment) >= 3
            and re.fullmatch(r"[0-9]+(?:\.[0-9]+)?[smhd]?", segment[1])
        ):
            segment = segment[2:]
        if segment[:1] == ["npx"]:
            segment = segment[1:]
            while segment[:1] in (["-y"], ["--yes"], ["--no-install"]):
                segment = segment[1:]
            if not segment or segment[0] not in {"tsx", "ts-node", "node"}:
                continue
        if not segment:
            continue
        executable, *arguments = segment
        name = executable if executable == "." else PurePosixPath(executable).name
        if name == "cd":
            cwd = literal(arguments[0]) if len(arguments) == 1 and connector == "&&" else None
            continue
        if name in {"source", "."}:
            if arguments:
                add_literal(arguments[0])
            continue
        is_python = bool(re.fullmatch(r"python(?:\d+(?:\.\d+)?)?", name))
        if name not in interpreters and not is_python:
            if "/" in executable:
                add_literal(executable)
            continue
        if name in {"bun", "deno"} and arguments[:1] == ["run"]:
            arguments = arguments[1:]
        index = 0
        while index < len(arguments):
            token = arguments[index]
            if token in {"-c", "-lc", "-ic"} and name in {"sh", "bash", "zsh", "dash"}:
                if _depth < 3 and index + 1 < len(arguments) and cwd is not None:
                    paths.update(
                        referenced_paths(arguments[index + 1], _depth=_depth + 1, _cwd=cwd)
                    )
                break
            if token in {"-e", "--eval", "-c"}:
                if index + 1 < len(arguments):
                    for target in _inline_file_loads(name, arguments[index + 1]):
                        add_literal(target)
                break
            if token.startswith("--eval="):
                for target in _inline_file_loads(name, token.split("=", 1)[1]):
                    add_literal(target)
                break
            if token == "-m" and is_python:
                break  # Module resolution is runtime-dependent.
            option = token.split("=", 1)[0]
            if name in {"node", "nodejs", "tsx", "ts-node"} and option in NODE_VALUE_OPTIONS:
                value = (
                    token.split("=", 1)[1]
                    if "=" in token
                    else (arguments[index + 1] if index + 1 < len(arguments) else "")
                )
                if option in NODE_LOAD_OPTIONS:
                    add_literal(value)
                index += 1 if "=" in token else 2
                continue
            if (is_python and token in PYTHON_VALUE_OPTIONS) or token.lower() == "-executionpolicy":
                index += 2
                continue
            if token.startswith("-"):
                index += 1
                continue
            add_literal(token)
            break
    return paths


def _config_root(path: str) -> str:
    parts = PurePosixPath(path).parts
    for index, part in enumerate(parts):
        if part.lower() in {".claude", ".vscode", ".codex", ".gemini", ".cursor"}:
            return PurePosixPath(*parts[:index]).as_posix() if index else ""
    parent = str(PurePosixPath(path).parent)
    return "" if parent == "." else parent


def atom_references(atom: PermissionAtom) -> set[str]:
    if atom.action == "auto_hook":
        command = atom.value
    elif atom.action == "folder_open_task":
        try:
            task = json.loads(atom.value)
        except ValueError:
            return set()
        if not isinstance(task, Mapping):
            return set()
        command = task_command(task)
        options = task.get("options")
        if isinstance(options, Mapping) and isinstance(options.get("cwd"), str):
            command = "cd " + shlex.quote(options["cwd"]) + " && " + command
    else:
        return set()
    return referenced_paths(command, _cwd=_config_root(atom.path))


def snapshot_hook_references(files: dict[str, str], cache: ConfigCache | None = None) -> set[str]:
    return {
        target
        for path, text in files.items()
        if project_config_kind(path)
        for atom in extract_project_atoms(path, text, cache)
        for target in atom_references(atom)
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


def is_auto_start(trigger: str) -> bool:
    # Credential helpers run without user action and next to credentials, so they
    # count as auto-start triggers alongside session start, folder open and status line.
    return trigger.lower() in {
        "sessionstart",
        "session_start",
        "folderopen",
        "statusline",
        "apikeyhelper",
        "awsauthrefresh",
        "awscredentialexport",
        "otelheadershelper",
    }


def persistence_findings(
    changes: list[PermissionChange], *, head_atoms: list[PermissionAtom] | None = None
) -> list[Finding]:
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
                if added and is_auto_start(atom.trigger)
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
                    and other.atom.actor == atom.actor
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
                and other.atom.actor == atom.actor
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
                        and other.atom.actor == atom.actor
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
            if not added:
                continue
            rule, title = "APD012", "New or modified executable referenced by an agent hook or task"
            severity = Severity.HIGH
        elif atom.action == "unparseable_config":
            rule, title = "APD008", "Unparseable startup config"
            severity = Severity.HIGH if added else Severity.LOW
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
    executables = [c for c in additions if c.atom.action == "hook_executable"]
    head = head_atoms if head_atoms is not None else [c.atom for c in additions]
    triggers = [a for a in head if a.action in {"auto_hook", "folder_open_task"}]
    starts = [c for c in executables if is_auto_start(c.atom.trigger)]
    claude = [a for a in triggers if a.action == "auto_hook" and a.surface == "claude"]
    tasks = [a for a in triggers if a.action == "folder_open_task"]
    added_keys = {c.atom.key() for c in additions}
    pair_changed = claude and tasks and any(a.key() in added_keys for a in [*claude, *tasks])
    if starts or pair_changed:
        selected = [a for a in triggers if any(a.actor == c.atom.actor for c in starts)]
        if pair_changed:
            selected.extend([*claude, *tasks])
        # Existing triggers are context, not new permissions. Keep them visible in the
        # correlated finding without adding them to the report's diff changes.
        by_key = {c.atom.key(): c for c in additions}
        context = {
            a.key(): by_key.get(a.key(), PermissionChange(kind="unchanged", atom=a))
            for a in selected
        }
        involved = [*context.values(), *starts]
        if pair_changed:
            involved.extend(c for c in executables if c not in starts)
        findings.append(
            Finding(
                rule_id="APD105",
                title="Worm-shaped persistence",
                severity=Severity.CRITICAL,
                summary=(
                    "New or changed startup execution, payloads, or paired Claude hooks and "
                    "folderOpen tasks resemble the "
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
