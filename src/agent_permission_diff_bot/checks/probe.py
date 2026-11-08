"""The Swallowed probe: inject the caught error and show what the caller gets instead.

For a Python handler that Swallowed reports, the probe rebuilds only that handler, puts a
``raise`` of the exception it catches where the ``try`` body was, and runs the result. It
reports how the error disappeared: the caller receives a value (often ``None``), execution
carries on after the ``try`` as if it succeeded, or a loop silently moves on.

What runs is limited by construction. Swallowed only reports handlers whose bodies contain
no calls, awaits, yields or raises, just ``pass``, constants, plain names, empty literals,
assignments of those, ``return``, ``continue`` and ``break``. The probe re-checks that,
compiles only the rebuilt handler, and runs it in an empty namespace with no builtins,
where every name the handler reads is a stand-in object. No project code, file or network
access is involved, so it is safe to run on pull request content inside the analysis
process (which is itself time- and memory-limited by ``run_limited``).

It does not run the protected code, so it shows what the handler does with an error, not
whether that error happens in practice.
"""

from __future__ import annotations

import ast
import builtins
import copy
from dataclasses import dataclass
from typing import Any, Literal

Outcome = Literal["vanished", "escaped", "not-probed"]


@dataclass(frozen=True)
class ProbeResult:
    outcome: Outcome
    injected: str = ""
    detail: str = ""

    def sentence(self) -> str:
        if self.outcome == "vanished":
            return (
                f"Probe: injecting `{self.injected}` into the `try` left no trace; {self.detail}."
            )
        if self.outcome == "escaped":
            return f"Probe: injecting `{self.injected}` escaped the handler ({self.detail})."
        return ""


class _StandIn:
    """What a name the handler reads evaluates to: inert, settable, hashable."""

    def __init__(self, name: str) -> None:
        object.__setattr__(self, "_name", name)

    def __getattr__(self, attribute: str) -> _StandIn:
        return _StandIn(f"{object.__getattribute__(self, '_name')}.{attribute}")

    def __setattr__(self, attribute: str, value: object) -> None:
        return None

    def __setitem__(self, key: object, value: object) -> None:
        return None

    def __getitem__(self, key: object) -> _StandIn:
        return _StandIn(f"{object.__getattribute__(self, '_name')}[...]")

    def __hash__(self) -> int:
        return hash(object.__getattribute__(self, "_name"))

    def __repr__(self) -> str:
        return f"the value of `{object.__getattribute__(self, '_name')}`"


def probe_python_handler(source: str, line: int) -> ProbeResult:
    """Probe the ``except`` clause that starts on ``line`` of ``source``."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return ProbeResult("not-probed", detail="the file did not parse")
    handler = next(
        (
            h
            for node in ast.walk(tree)
            if isinstance(node, (ast.Try, ast.TryStar))
            for h in node.handlers
            if h.lineno == line
        ),
        None,
    )
    if handler is None or not _only_inert(handler):
        return ProbeResult("not-probed", detail="no call-free handler starts on that line")
    injected_name, injected = _injected_exception(handler.type)
    namespace: dict[str, Any] = {"__builtins__": {}, "__Injected__": injected}
    for name in _names_read(handler):
        namespace[name] = _StandIn(name)
    code = compile(_probe_module(handler), "<swallowed-probe>", "exec")
    exec(code, namespace)
    try:
        kind, value = namespace["__probe__"]()
    except BaseException as exc:  # the handler let the injected error (or another) out
        return ProbeResult("escaped", injected_name, f"it raised `{type(exc).__name__}`")
    return ProbeResult("vanished", injected_name, _describe(kind, value))


def _describe(kind: str, value: object) -> str:
    if kind == "returned":
        return f"the caller gets {_shown(value)} instead of an error"
    if kind == "continued":
        return "the loop moves on to its next item as if this one succeeded"
    if kind == "broke":
        return "the loop stops early as if it had finished"
    return "execution continues after the `try` as if it had succeeded"


def _shown(value: object) -> str:
    if isinstance(value, _StandIn):
        return repr(value)
    return f"`{value!r}`"


def _only_inert(handler: ast.ExceptHandler) -> bool:
    allowed = (ast.Pass, ast.Continue, ast.Break, ast.Expr, ast.Return, ast.Assign, ast.AnnAssign)
    for statement in handler.body:
        if not isinstance(statement, allowed):
            return False
        for node in ast.walk(statement):
            if isinstance(
                node,
                (
                    ast.Call,
                    ast.Await,
                    ast.Yield,
                    ast.YieldFrom,
                    ast.Raise,
                    ast.Lambda,
                    ast.NamedExpr,
                    ast.comprehension,
                    ast.FunctionDef,
                    ast.AsyncFunctionDef,
                    ast.ClassDef,
                ),
            ):
                return False
    return True


def _injected_exception(node: ast.expr | None) -> tuple[str, type[BaseException]]:
    """The exception to raise: what the handler catches, or a stand-in class of that name."""
    if node is None:
        return "RuntimeError", RuntimeError
    first = node.elts[0] if isinstance(node, ast.Tuple) and node.elts else node
    dotted = _dotted(first) or "Exception"
    name = dotted.rsplit(".", 1)[-1]
    found = getattr(builtins, name, None)
    if isinstance(found, type) and issubclass(found, BaseException):
        return dotted, found
    return dotted, type(name, (Exception,), {})


def _dotted(node: ast.expr) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        inner = _dotted(node.value)
        return f"{inner}.{node.attr}" if inner else node.attr
    return ""


def _names_read(handler: ast.ExceptHandler) -> set[str]:
    names = {
        node.id
        for statement in handler.body
        for node in ast.walk(statement)
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)
    }
    names.discard(handler.name or "")
    return names


class _Outcomes(ast.NodeTransformer):
    """``return v`` / ``continue`` / ``break`` become a tagged return the probe can read."""

    def visit_Return(self, node: ast.Return) -> ast.AST:
        value = node.value or ast.Constant(None)
        return ast.copy_location(
            ast.Return(ast.Tuple([ast.Constant("returned"), value], ast.Load())), node
        )

    def visit_Continue(self, node: ast.Continue) -> ast.AST:
        return ast.copy_location(_tagged("continued"), node)

    def visit_Break(self, node: ast.Break) -> ast.AST:
        return ast.copy_location(_tagged("broke"), node)


def _tagged(kind: str) -> ast.Return:
    return ast.Return(ast.Tuple([ast.Constant(kind), ast.Constant(None)], ast.Load()))


def _probe_module(handler: ast.ExceptHandler) -> ast.Module:
    body = [_Outcomes().visit(copy.deepcopy(statement)) for statement in handler.body]
    probe_handler = ast.ExceptHandler(
        type=ast.Name("__Injected__", ast.Load()), name=handler.name, body=body or [ast.Pass()]
    )
    raise_injected = ast.Raise(
        exc=ast.Call(
            ast.Name("__Injected__", ast.Load()),
            [ast.Constant("injected by the Swallowed probe")],
            [],
        )
    )
    fields: dict[str, Any] = {
        "name": "__probe__",
        "args": ast.arguments([], [], None, [], [], None, []),
        "body": [
            ast.Try(body=[raise_injected], handlers=[probe_handler], orelse=[], finalbody=[]),
            _tagged("fell-through"),
        ],
        "decorator_list": [],
        "returns": None,
    }
    if "type_params" in ast.FunctionDef._fields:  # Python 3.12 and later
        fields["type_params"] = []
    function = ast.FunctionDef(**fields)
    module = ast.Module(body=[function], type_ignores=[])
    return ast.fix_missing_locations(module)
