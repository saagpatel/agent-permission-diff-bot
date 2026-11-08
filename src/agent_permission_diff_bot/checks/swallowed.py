"""Swallowed: new places in a diff where an error is caught and dropped.

A handler counts as swallowing when it neither re-raises, nor calls anything
(such as a logger), nor uses the caught error: its body is only ``pass``,
``continue``, ``break``, a constant return or a constant assignment. Only
handlers whose lines the pull request adds or changes are reported.

Findings are ranked by what the protected code does, read from the names it
calls: authentication first (a dropped failure can let a request through), then
data loss (writes, deletes, commits), then network calls, then anything else.

Python is parsed with :mod:`ast`; TypeScript and JavaScript with tree-sitter
(part of the ``app`` extra). Nothing is executed. A handler marked
``swallowed: ok <reason>`` in a comment is listed as deliberate, not ranked.
"""

from __future__ import annotations

import ast
import io
import re
import tokenize
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any

from agent_permission_diff_bot.checks.model import (
    CheckFinding,
    CheckResult,
    DeliberateCatch,
    rank,
)
from agent_permission_diff_bot.checks.probe import parent_map, probe_handler
from agent_permission_diff_bot.model import Severity

MAX_FILE_BYTES = 1024 * 1024
PYTHON_SUFFIXES = (".py", ".pyi")
TS_SUFFIXES = (".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs")

_MARKER_RE = re.compile(r"swallowed:\s*ok\b[\s:,-]*(?P<reason>[^\n]*)", re.IGNORECASE)
_NOQA_RE = re.compile(r"noqa:[^\n]*\b(S110|S112|BLE001|SIM105)\b", re.IGNORECASE)

# Name fragments, matched against the words of called names (split on . and _ and case).
_CATEGORY_WORDS: tuple[tuple[str, frozenset[str]], ...] = (
    (
        "auth",
        frozenset(
            {
                "auth",
                "authenticate",
                "authorize",
                "authorized",
                "token",
                "jwt",
                "verify",
                "login",
                "password",
                "permission",
                "permissions",
                "credential",
                "credentials",
                "signature",
                "oauth",
                "acl",
                "role",
                "roles",
                "csrf",
                "otp",
                "mfa",
            }
        ),
    ),
    (
        "data-loss",
        frozenset(
            {
                "write",
                "writefile",
                "save",
                "commit",
                "delete",
                "remove",
                "unlink",
                "rmtree",
                "rm",
                "rmdir",
                "rename",
                "dump",
                "flush",
                "insert",
                "update",
                "upsert",
                "execute",
                "executemany",
                "truncate",
                "migrate",
                "persist",
                "destroy",
                "transaction",
                "setitem",
                "move",
                "copyfile",
                "bulk",
                "drop",
            }
        ),
    ),
    (
        "network",
        frozenset(
            {
                "requests",
                "httpx",
                "aiohttp",
                "urllib",
                "urlopen",
                "http",
                "https",
                "fetch",
                "axios",
                "socket",
                "connect",
                "send",
                "sendall",
                "recv",
                "request",
                "post",
                "smtp",
                "smtplib",
                "boto3",
                "grpc",
                "websocket",
                "publish",
                "subscribe",
                "webhook",
                "download",
                "upload",
                "got",
                "ky",
            }
        ),
    ),
)

_SEVERITY = {
    "auth": Severity.HIGH,
    "data-loss": Severity.HIGH,
    "network": Severity.MEDIUM,
    "other": Severity.LOW,
}
_HIDES = {
    "auth": "an authentication or permission failure, so the code carries on as if it passed",
    "data-loss": "a failed write or delete, so data is lost with no error anywhere",
    "network": "a failed network call, so the caller sees missing data instead of an error",
    "other": "an unexpected error, so the next failure shows up somewhere else",
}
_FIX = {
    "auth": "Let it raise, or deny explicitly in the handler; never continue after a failed check.",
    "data-loss": (
        "Re-raise, or log the error and return a failure the caller must handle "
        "before anything is reported as saved."
    ),
    "network": (
        "Catch the specific error (such as a timeout), log it with the request, "
        "and retry or surface it."
    ),
    "other": "Narrow the exception type and log it, or mark it `swallowed: ok <reason>`.",
}
_BROAD_PY = {"Exception", "BaseException"}
_NARROW_PY = {
    "FileNotFoundError",
    "KeyError",
    "IndexError",
    "StopIteration",
    "StopAsyncIteration",
    "ImportError",
    "ModuleNotFoundError",
    "AttributeError",
    "NotImplementedError",
    "ProcessLookupError",
    "FileExistsError",
    "IsADirectoryError",
}


@dataclass(frozen=True)
class ChangedFile:
    """A file in the pull request: its head text and the head lines the PR touches.

    ``changed`` holds the 1-based head lines the PR adds, plus the head lines on either side
    of anything it deletes, so a handler made silent only by deleting a line still counts.
    """

    path: str
    text: str
    changed: frozenset[int]


@dataclass(frozen=True)
class _Catch:
    path: str
    line: int
    lines: range
    protected_names: tuple[str, ...]
    caught: str
    broad: bool
    narrow: bool
    language: str
    probe: str = ""  # the probe's sentence, worked out from the already parsed tree


def scan_swallowed(files: Iterable[ChangedFile]) -> CheckResult:
    result = CheckResult(check="swallowed")
    ts_files: list[ChangedFile] = []
    findings: list[CheckFinding] = []
    for changed in files:
        if not changed.changed:
            continue
        if len(changed.text.encode("utf-8", errors="surrogateescape")) > MAX_FILE_BYTES:
            result.notes.append(f"`{changed.path}` is over 1 MiB and was not scanned.")
            continue
        suffix = PurePosixPath(changed.path).suffix.lower()
        if suffix in PYTHON_SUFFIXES:
            catches = _python_catches(changed, result.notes)
            comments = _python_comments(changed.text)
        elif suffix in TS_SUFFIXES:
            ts_files.append(changed)
            continue
        else:
            continue
        _classify(changed, catches, comments, findings, result.deliberate)
    if ts_files:
        parser = _ts_parsers()
        if parser is None:
            result.notes.append(
                f"{len(ts_files)} TypeScript/JavaScript file(s) were not scanned: "
                "install the `app` extra for tree-sitter."
            )
        else:
            for changed in ts_files:
                catches, comments = _ts_catches(changed, parser)
                _classify(changed, catches, comments, findings, result.deliberate)
    result.findings = rank(findings)
    return result


def changed_lines_from_patch(patch: str) -> frozenset[int]:
    """Head lines a unified diff hunk adds, plus the head lines around each deletion."""
    changed: set[int] = set()
    line = 0
    for raw in patch.splitlines():
        if raw.startswith("@@"):
            match = re.match(r"@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@", raw)
            line = int(match.group(1)) if match else 0
            continue
        if not line:
            continue
        # GitHub's patch field has no file headers, so the first character alone decides:
        # a removed `----------` docstring underline is a removal, not a header.
        marker = raw[:1]
        if marker == "+":
            changed.add(line)
            line += 1
        elif marker == "-":
            # A deletion sits between head lines line-1 and line; both are touched.
            changed.update(n for n in (line - 1, line) if n > 0)
        elif marker == "\\":
            continue
        else:
            line += 1
    return frozenset(changed)


def changed_lines_between(base: str, head: str) -> frozenset[int]:
    """Head lines that are new, or next to a deletion, compared with ``base``."""
    import difflib

    matcher = difflib.SequenceMatcher(a=base.splitlines(), b=head.splitlines(), autojunk=False)
    changed: set[int] = set()
    for tag, _i1, _i2, j1, j2 in matcher.get_opcodes():
        if tag in {"insert", "replace"}:
            changed.update(range(j1 + 1, j2 + 1))
        elif tag == "delete":
            changed.update(n for n in (j1, j1 + 1) if n > 0)
    return frozenset(changed)


# --- classification ------------------------------------------------------------------------


def _classify(
    changed: ChangedFile,
    catches: Iterable[_Catch],
    comments: Mapping[int, str],
    findings: list[CheckFinding],
    deliberate: list[DeliberateCatch],
) -> None:
    for catch in catches:
        if not any(line in changed.changed for line in catch.lines):
            continue
        # Markers count only in real comments, never inside a string literal.
        comment_text = "\n".join(comments[n] for n in catch.lines if n in comments)
        marker = _MARKER_RE.search(comment_text)
        noqa = _NOQA_RE.search(comment_text)
        if marker or noqa:
            if marker:
                reason = marker.group("reason").strip() or "no reason given"
            else:
                code = noqa.group(1) if noqa else ""
                reason = f"lint suppression `noqa: {code}`, no reason given"
            deliberate.append(DeliberateCatch(path=catch.path, line=catch.line, reason=reason))
            continue
        category = _category(catch.protected_names)
        severity = _SEVERITY[category]
        notes: list[str] = []
        if catch.broad and category == "other":
            severity = Severity.MEDIUM
        if catch.caught in {"bare except", "BaseException"}:
            notes.append("It also swallows Ctrl-C and `sys.exit()`.")
        called = _called_summary(catch.protected_names, category)
        allows = [f"Can hide {_HIDES[category]}{called}.", *notes]
        if catch.narrow and category == "other":
            allows = [
                f"Probably deliberate: only `{catch.caught}` is dropped, and the protected code "
                "does not write, authenticate or call the network."
            ]
        if catch.probe:
            allows.insert(1, catch.probe)
        findings.append(
            CheckFinding(
                check="swallowed",
                rule_id=f"SW-{category}",
                severity=severity,
                title=f"`{catch.caught}` dropped" + _title_suffix(category),
                path=catch.path,
                line=catch.line,
                allows=tuple(allows),
                fix=_FIX[category],
                category=category,
            )
        )


def _title_suffix(category: str) -> str:
    return {
        "auth": " around an auth check",
        "data-loss": " around a write",
        "network": " around a network call",
    }.get(category, "")


def _category(names: Iterable[str]) -> str:
    words = {word for name in names for word in _words(name)}
    for category, vocabulary in _CATEGORY_WORDS:
        if words & vocabulary:
            return category
    return "other"


def _called_summary(names: Iterable[str], category: str) -> str:
    if category == "other":
        return ""
    vocabulary = dict(_CATEGORY_WORDS)[category]
    hits = [name for name in names if set(_words(name)) & vocabulary]
    unique = list(dict.fromkeys(hits))[:2]
    return " (calls " + ", ".join(f"`{name}`" for name in unique) + ")" if unique else ""


def _words(name: str) -> list[str]:
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", name)
    return [w.lower() for w in re.split(r"[^A-Za-z0-9]+", spaced) if w]


# --- Python ----------------------------------------------------------------------------------


def _python_comments(text: str) -> dict[int, str]:
    """Comment text by 1-based line, from the tokenizer (so strings never count)."""
    comments: dict[int, str] = {}
    try:
        for token in tokenize.generate_tokens(io.StringIO(text).readline):
            if token.type == tokenize.COMMENT:
                comments[token.start[0]] = token.string
    except (tokenize.TokenError, SyntaxError, IndentationError):
        pass  # the file did not parse; _python_catches already noted it
    return comments


def _python_catches(changed: ChangedFile, notes: list[str]) -> list[_Catch]:
    try:
        tree = ast.parse(changed.text, filename=changed.path)
    except SyntaxError as exc:
        notes.append(f"`{changed.path}` did not parse as Python (line {exc.lineno}); not scanned.")
        return []
    catches: list[_Catch] = []
    parents = parent_map(tree)
    for node in ast.walk(tree):
        if isinstance(node, (ast.Try, ast.TryStar)):
            names = tuple(_called_names(node.body))
            for handler in node.handlers:
                if not _python_swallows(handler):
                    continue
                caught = _caught_name(handler.type)
                end = handler.end_lineno or handler.lineno
                catches.append(
                    _Catch(
                        path=changed.path,
                        line=handler.lineno,
                        lines=range(handler.lineno, end + 1),
                        protected_names=names,
                        caught=caught,
                        broad=caught in _BROAD_PY or caught == "bare except",
                        narrow=_all_narrow(handler.type),
                        language="python",
                        probe=probe_handler(node, handler, parents).sentence(),
                    )
                )
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                call = item.context_expr
                if (
                    isinstance(call, ast.Call)
                    and _dotted(call.func).split(".")[-1] == "suppress"
                    and call.args
                ):
                    types = [_dotted(arg) for arg in call.args]
                    caught = ", ".join(types)
                    end = node.end_lineno or node.lineno
                    catches.append(
                        _Catch(
                            path=changed.path,
                            line=node.lineno,
                            lines=range(node.lineno, end + 1),
                            protected_names=tuple(_called_names(node.body)),
                            caught=f"suppress({caught})",
                            broad=any(t.split(".")[-1] in _BROAD_PY for t in types),
                            narrow=all(t.split(".")[-1] in _NARROW_PY for t in types),
                            language="python",
                        )
                    )
    return catches


def _python_swallows(handler: ast.ExceptHandler) -> bool:
    for statement in handler.body:
        for node in ast.walk(statement):
            if isinstance(node, (ast.Raise, ast.Call, ast.Await, ast.Yield, ast.YieldFrom)):
                return False
            if (
                handler.name
                and isinstance(node, ast.Name)
                and node.id == handler.name
                and isinstance(node.ctx, ast.Load)
            ):
                return False
        if isinstance(statement, (ast.Pass, ast.Continue, ast.Break)):
            continue
        if isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Constant):
            continue
        if isinstance(statement, ast.Return) and _is_plain_value(statement.value):
            continue
        if isinstance(statement, (ast.Assign, ast.AnnAssign)) and _is_plain_value(statement.value):
            continue
        return False
    return True


def _is_plain_value(node: ast.expr | None) -> bool:
    if node is None or isinstance(node, (ast.Constant, ast.Name)):
        return True
    if isinstance(node, ast.UnaryOp):
        return isinstance(node.operand, ast.Constant)
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return not node.elts
    if isinstance(node, ast.Dict):
        return not node.keys
    return False


def _caught_name(node: ast.expr | None) -> str:
    if node is None:
        return "bare except"
    if isinstance(node, ast.Tuple):
        return ", ".join(_dotted(elt) for elt in node.elts)
    return _dotted(node)


def _all_narrow(node: ast.expr | None) -> bool:
    if node is None:
        return False
    elements = node.elts if isinstance(node, ast.Tuple) else [node]
    return all(_dotted(elt).split(".")[-1] in _NARROW_PY for elt in elements)


def _called_names(body: list[ast.stmt]) -> Iterable[str]:
    for statement in body:
        for node in ast.walk(statement):
            if isinstance(node, ast.Call):
                name = _dotted(node.func)
                if name:
                    yield name


def _dotted(node: ast.expr) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        inner = _dotted(node.value)
        return f"{inner}.{node.attr}" if inner else node.attr
    if isinstance(node, ast.Call):
        return _dotted(node.func)
    if isinstance(node, ast.Subscript):
        return _dotted(node.value)
    return ""


# --- TypeScript / JavaScript -----------------------------------------------------------------


def _ts_parsers() -> Mapping[str, Any] | None:
    try:
        import tree_sitter_typescript
        from tree_sitter import Language, Parser
    except ImportError:
        return None
    return {
        "ts": Parser(Language(tree_sitter_typescript.language_typescript())),
        "tsx": Parser(Language(tree_sitter_typescript.language_tsx())),
    }


def _ts_catches(
    changed: ChangedFile, parsers: Mapping[str, Any]
) -> tuple[list[_Catch], dict[int, str]]:
    suffix = PurePosixPath(changed.path).suffix.lower()
    parser = parsers["tsx" if suffix in {".tsx", ".jsx"} else "ts"]
    source = changed.text.encode("utf-8", errors="surrogateescape")
    tree = parser.parse(source)
    catches: list[_Catch] = []
    comments: dict[int, str] = {}
    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        stack.extend(node.children)
        if node.type == "comment":
            text = _text(node)
            for row in range(node.start_point[0] + 1, node.end_point[0] + 2):
                comments[row] = (comments.get(row, "") + " " + text).strip()
            continue
        if node.type == "catch_clause":
            body = node.child_by_field_name("body")
            if body is None or not _ts_block_swallows(body, node):
                continue
            protected = node.parent.child_by_field_name("body") if node.parent else None
            catches.append(_ts_catch(changed, node, protected, "catch"))
        elif node.type == "call_expression":
            function = node.child_by_field_name("function")
            arguments = node.child_by_field_name("arguments")
            if (
                function is None
                or arguments is None
                or function.type != "member_expression"
                or _text(function.child_by_field_name("property")) != "catch"
            ):
                continue
            handlers = [child for child in arguments.named_children if child.type != "comment"]
            if len(handlers) != 1 or not _ts_handler_swallows(handlers[0]):
                continue
            catches.append(
                _ts_catch(changed, node, function.child_by_field_name("object"), ".catch()")
            )
    return catches, comments


def _ts_catch(changed: ChangedFile, node: Any, protected: Any, caught: str) -> _Catch:
    start = node.start_point[0] + 1
    end = node.end_point[0] + 1
    if caught == ".catch()":
        # A promise chain can be long; the handler's own lines are what the PR adds.
        start = node.child_by_field_name("arguments").start_point[0] + 1
    return _Catch(
        path=changed.path,
        line=start,
        lines=range(start, end + 1),
        protected_names=tuple(_ts_called_names(protected)),
        caught=caught,
        broad=True,
        narrow=False,
        language="typescript",
    )


def _ts_block_swallows(block: Any, clause: Any) -> bool:
    param = clause.child_by_field_name("parameter")
    param_name = _text(param) if param is not None and param.type == "identifier" else ""
    for statement in block.named_children:
        if statement.type in {"comment", "empty_statement"}:
            continue
        if statement.type in {"continue_statement", "break_statement"}:
            continue
        if statement.type == "return_statement":
            values = [c for c in statement.named_children if c.type != "comment"]
            if not values or _ts_plain(values[0], param_name):
                continue
        if statement.type == "expression_statement" and _ts_plain_assignment(statement, param_name):
            continue
        return False
    return True


def _ts_plain_assignment(statement: Any, *forbidden: str) -> bool:
    """`ok = false;` or `this.failed = true;`: a flag set, the error itself dropped."""
    expressions = [c for c in statement.named_children if c.type != "comment"]
    if len(expressions) != 1 or expressions[0].type != "assignment_expression":
        return False
    left = expressions[0].child_by_field_name("left")
    right = expressions[0].child_by_field_name("right")
    return (
        left is not None
        and _ts_plain_target(left, *forbidden)
        and right is not None
        and _ts_plain(right, *forbidden)
    )


_TS_WRAPPERS = frozenset(
    {"non_null_expression", "parenthesized_expression", "as_expression", "satisfies_expression"}
)


def _ts_plain_target(node: Any, *forbidden: str) -> bool:
    """`ok`, `this.failed`, `state.last.ok` or `failed[key]`: no call, and the caught error
    is not used."""
    if node.type == "identifier":
        return _text(node) not in forbidden
    if node.type == "this":
        return True
    if node.type in _TS_WRAPPERS and node.named_children:
        # `state!.failed`, `(this as any).failed`, `(x satisfies T).ok`, `(ok)`
        return _ts_plain_target(node.named_children[0], *forbidden)
    if node.type == "member_expression":
        target = node.child_by_field_name("object")
        prop = node.child_by_field_name("property")
        return (
            target is not None
            and prop is not None
            and prop.type in {"property_identifier", "private_property_identifier"}
            and _ts_plain_target(target, *forbidden)
        )
    if node.type == "subscript_expression":
        target = node.child_by_field_name("object")
        index = node.child_by_field_name("index")
        return (
            target is not None
            and index is not None
            and _ts_plain_target(target, *forbidden)
            and _ts_plain(index, *forbidden)
        )
    return False


def _ts_handler_swallows(handler: Any) -> bool:
    if handler.type in {"arrow_function", "function_expression", "function"}:
        body = handler.child_by_field_name("body")
        if body is None:
            return False
        params = handler.child_by_field_name("parameters") or handler.child_by_field_name(
            "parameter"
        )
        names = _ts_identifiers(params) if params is not None else set()
        if body.type == "statement_block":
            for statement in body.named_children:
                if statement.type in {"comment", "empty_statement"}:
                    continue
                if statement.type == "return_statement":
                    values = [c for c in statement.named_children if c.type != "comment"]
                    if not values or _ts_plain(values[0], *names):
                        continue
                if statement.type == "expression_statement" and _ts_plain_assignment(
                    statement, *names
                ):
                    continue
                return False
            return True
        return _ts_plain(body, *names)
    return handler.type == "identifier" and _text(handler) in {"noop", "_noop", "ignore"}


def _ts_plain(node: Any, *forbidden: str) -> bool:
    if node.type in {"null", "undefined", "true", "false", "number", "string"}:
        return True
    if node.type == "identifier":
        return _text(node) not in forbidden
    if node.type in {"array", "object"}:
        return not node.named_children
    if node.type == "parenthesized_expression" and node.named_children:
        return _ts_plain(node.named_children[0], *forbidden)
    if node.type == "unary_expression":
        argument = node.child_by_field_name("argument")
        return argument is not None and argument.type != "identifier" and _ts_plain(argument)
    return False


def _ts_identifiers(node: Any) -> set[str]:
    found: set[str] = set()
    stack = [node]
    while stack:
        current = stack.pop()
        if current.type == "identifier":
            found.add(_text(current))
        stack.extend(current.children)
    return found


def _ts_called_names(node: Any) -> Iterable[str]:
    if node is None:
        return
    stack = [node]
    while stack:
        current = stack.pop()
        if current.type in {"call_expression", "new_expression"}:
            callee = current.child_by_field_name("function") or current.child_by_field_name(
                "constructor"
            )
            if callee is not None and callee.type in {"identifier", "member_expression"}:
                yield _text(callee).replace("?.", ".")
        stack.extend(current.children)


def _text(node: Any) -> str:
    if node is None:
        return ""
    raw = node.text
    return raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else ""
