"""The Swallowed probe: inject the caught error and show what the caller gets instead.

For a Python handler that Swallowed reports, the probe works out what happens when the
exception it catches is raised inside its ``try``: the caller receives a value (often
``None``), execution carries on after the ``try`` as if it succeeded, or a loop silently
moves on or stops.

Nothing is executed. Swallowed only reports handlers that are straight-line code with no
calls, awaits, yields or raises: ``pass``, constants, names, empty literals, assignments of
those, ``return``, ``continue`` and ``break``. For such a body the outcome is fully
determined by its statements in order, so the probe reads them rather than running them.
Running pull request expressions, even in a trimmed namespace, is not safe: attribute
chains reach real objects. Proving that the error happens in practice would mean running
the project's own code, which this probe deliberately does not do.
"""

from __future__ import annotations

import ast
import builtins
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal

Outcome = Literal["vanished", "not-probed"]


@dataclass(frozen=True)
class ProbeResult:
    outcome: Outcome
    injected: str = ""
    detail: str = ""

    def sentence(self) -> str:
        if self.outcome != "vanished":
            return ""
        injected = f"`{self.injected}`"
        return f"Probe: injecting {injected} into the `try` leaves no trace; {self.detail}."


def probe_python_handler(source: str, line: int) -> ProbeResult:
    """Probe the ``except`` clause that starts on ``line`` of ``source``."""
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return ProbeResult("not-probed", detail="the file did not parse")
    found = next(
        (
            (node, h)
            for node in ast.walk(tree)
            if isinstance(node, (ast.Try, ast.TryStar))
            for h in node.handlers
            if h.lineno == line
        ),
        None,
    )
    if found is None:
        return ProbeResult("not-probed", detail="no handler starts on that line")
    return probe_handler(found[0], found[1], file_context(tree))


@dataclass(frozen=True)
class FileContext:
    """What the probe needs from the whole parsed file, built once per file."""

    parents: Mapping[ast.AST, ast.AST]
    # Names some binding in the file can make local or free: any assignment, deletion,
    # parameter, import, definition, `except ... as`, match capture or global/nonlocal
    # declaration, in any scope. A builtin is trusted only if it is in none of these.
    bound_anywhere: frozenset[str]
    # Names that can be unbound again: deleted, an `except ... as` target (unbound when that
    # handler ends) or declared global/nonlocal, anywhere in the file.
    unbound_anywhere: frozenset[str]


def file_context(tree: ast.AST) -> FileContext:
    """Parent links and file-wide binding facts for :func:`probe_handler`."""
    parents: dict[ast.AST, ast.AST] = {}
    bound: set[str] = set()
    unbound: set[str] = set()
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parents[child] = node
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            bound.add(node.id)
            if isinstance(node.ctx, ast.Del):
                unbound.add(node.id)
        elif isinstance(node, ast.arg):
            bound.add(node.arg)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            bound.add(node.name)
            unbound.add(node.name)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            bound |= {(a.asname or a.name).split(".")[0] for a in node.names if a.name != "*"}
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            bound.add(node.name)
        elif isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name:
            bound |= {node.name}  # a match capture binds like an assignment
        elif isinstance(node, ast.MatchMapping) and node.rest:
            bound.add(node.rest)
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            bound |= set(node.names)
            unbound |= set(node.names)
    return FileContext(parents, frozenset(bound), frozenset(unbound))


def probe_handler(
    statement: ast.Try | ast.TryStar,
    handler: ast.ExceptHandler,
    context: FileContext,
) -> ProbeResult:
    """Probe one handler of an already parsed ``try`` statement.

    ``context`` is the file's :func:`file_context`. The probe refuses a ``try`` with
    ``finally`` or ``else``, a handler after another ``except`` clause (which may catch the
    error first), one inside an enclosing ``finally`` or ``with`` block, and one that reads
    a name that may be unbound.
    """
    if statement.finalbody or statement.orelse:
        # A `finally` can return or raise over the handler, and an `else` changes what the
        # success path does; the outcome is no longer just the handler's.
        return ProbeResult("not-probed", detail="the try has a finally or else block")
    if handler is not statement.handlers[0]:
        # Exception classes are not resolved, so any earlier clause may catch it first.
        return ProbeResult("not-probed", detail="an earlier `except` clause may catch it first")
    enclosing = _enclosing_exit(statement, context.parents)
    if enclosing:
        return ProbeResult("not-probed", detail=f"an enclosing `{enclosing}` runs after it")
    if not _straight_line(handler):
        return ProbeResult("not-probed", detail="the handler is not plain, call-free code")
    unbound = _first_unbound_read(handler, _bound_before(statement, context))
    if unbound:
        return ProbeResult("not-probed", detail=f"the handler reads `{unbound}`, maybe unbound")
    return ProbeResult("vanished", _injected_name(handler.type), _outcome(handler))


_SCOPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef, ast.Module)
# Builtins every interpreter has: no private names, and none that `site` adds.
_ALWAYS_BOUND = frozenset(
    name
    for name in dir(builtins)
    if not name.startswith("_")
    and name not in {"exit", "quit", "help", "copyright", "credits", "license"}
)


def _enclosing_exit(node: ast.AST, parents: Mapping[ast.AST, ast.AST]) -> str:
    """``finally`` or ``with`` if one encloses ``node`` in the same function: either runs
    after the handler and can raise over its result. Empty otherwise."""
    current = parents.get(node)
    while current is not None and not isinstance(current, _SCOPES):
        if isinstance(current, (ast.Try, ast.TryStar)) and current.finalbody:
            return "finally"
        if isinstance(current, (ast.With, ast.AsyncWith)):
            return "with"
        current = parents.get(current)
    return ""


def _bound_before(statement: ast.AST, context: FileContext) -> set[str]:
    """Names certainly bound when ``statement`` runs.

    Builtins that nothing in the file binds (any binding of the name could make it local or
    a closure over an empty cell), the enclosing function's parameters, and names its scope
    assigns in straight-line statements before it. Names that can be unbound again anywhere
    in the file are never counted.
    """
    parents = context.parents
    bound = set(_ALWAYS_BOUND - context.bound_anywhere)
    child, scope = statement, parents.get(statement)
    while scope is not None and not isinstance(scope, _SCOPES):
        child, scope = scope, parents.get(scope)
    if scope is not None and not isinstance(scope, ast.Lambda):
        if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
            arguments = scope.args
            for arg in [*arguments.posonlyargs, *arguments.args, *arguments.kwonlyargs]:
                bound.add(arg.arg)
            for extra in (arguments.vararg, arguments.kwarg):
                if extra is not None:
                    bound.add(extra.arg)
        for earlier in scope.body:
            if earlier is child:
                break
            bound |= _binds(earlier)
    return bound - context.unbound_anywhere


def _binds(statement: ast.stmt) -> set[str]:
    """Names an unconditional statement binds once it has run."""
    if isinstance(statement, ast.Assign):
        return {n.id for t in statement.targets for n in ast.walk(t) if isinstance(n, ast.Name)}
    if isinstance(statement, ast.AnnAssign) and statement.value is not None:
        return {n.id for n in ast.walk(statement.target) if isinstance(n, ast.Name)}
    if isinstance(statement, (ast.Import, ast.ImportFrom)):
        return {(a.asname or a.name).split(".")[0] for a in statement.names if a.name != "*"}
    if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return {statement.name}
    return set()


def _first_unbound_read(handler: ast.ExceptHandler, bound: set[str]) -> str:
    """The first name the handler reads that is not certainly bound at that point."""
    known = set(bound)
    if handler.name:
        known.add(handler.name)
    for statement in handler.body:
        # An annotation is evaluated at module and class scope, so its names count as reads.
        reads = [getattr(statement, "value", None), getattr(statement, "annotation", None)]
        for value in (r for r in reads if r is not None):
            for node in ast.walk(value):
                if isinstance(node, ast.Name) and node.id not in known:
                    return node.id
        if isinstance(statement, ast.Assign):
            known |= {t.id for t in statement.targets if isinstance(t, ast.Name)}
        elif (
            isinstance(statement, ast.AnnAssign)
            and isinstance(statement.target, ast.Name)
            and statement.value is not None
        ):
            known.add(statement.target.id)
    return ""


def _outcome(handler: ast.ExceptHandler) -> str:
    """What the caller sees, reading the handler's statements in order."""
    known: dict[str, str] = {}  # names this handler assigned, and what they now hold
    for statement in handler.body:
        if isinstance(statement, ast.Return):
            return f"the caller gets {_describe(statement.value, known)} instead of an error"
        if isinstance(statement, ast.Continue):
            return "the loop moves on to its next item as if this one succeeded"
        if isinstance(statement, ast.Break):
            return "the loop stops early as if it had finished"
        if isinstance(statement, ast.Assign):
            value = _describe(statement.value, known)
            for target in statement.targets:  # `a = b = x` sets both
                if isinstance(target, ast.Name):
                    known[target.id] = value
        elif isinstance(statement, ast.AnnAssign) and isinstance(statement.target, ast.Name):
            if statement.value is not None:
                known[statement.target.id] = _describe(statement.value, known)
    return "execution continues after the `try` as if it had succeeded"


def _describe(value: ast.expr | None, known: dict[str, str]) -> str:
    if value is None:
        return "`None`"
    if isinstance(value, ast.Name):
        return known.get(value.id, f"the value of `{value.id}`")
    try:
        literal = ast.literal_eval(value)
    except (ValueError, TypeError, SyntaxError, RecursionError, MemoryError):
        return f"`{ast.unparse(value)}`"
    return f"`{literal!r}`"


def _straight_line(handler: ast.ExceptHandler) -> bool:
    """Only the statement kinds Swallowed reports, with nothing that could run code."""
    allowed = (ast.Pass, ast.Continue, ast.Break, ast.Expr, ast.Return, ast.Assign, ast.AnnAssign)
    for statement in handler.body:
        if not isinstance(statement, allowed):
            return False
        if isinstance(statement, ast.Expr) and not isinstance(statement.value, ast.Constant):
            return False
        # Only plain names are assigned: unpacking can fail at run time, and an attribute
        # or subscript assignment can run a `__setattr__` / `__setitem__` the probe cannot see.
        if isinstance(statement, ast.Assign) and not all(
            isinstance(target, ast.Name) for target in statement.targets
        ):
            return False
        if isinstance(statement, ast.AnnAssign) and not isinstance(statement.target, ast.Name):
            return False
        # Values are constants, names and literal lists, tuples and dicts of those: an
        # operator, attribute read or subscript can raise or run code.
        value = getattr(statement, "value", None)
        if value is not None and not _inert(value):
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
                ),
            ):
                return False
    return True


def _inert(value: ast.expr) -> bool:
    if isinstance(value, (ast.Constant, ast.Name)):
        return True
    if isinstance(value, ast.UnaryOp) and isinstance(value.op, (ast.USub, ast.UAdd)):
        operand = value.operand
        return isinstance(operand, ast.Constant) and type(operand.value) in (int, float, complex)
    if isinstance(value, (ast.Tuple, ast.List)):
        return all(_inert(element) for element in value.elts)
    if isinstance(value, ast.Dict):
        return all(isinstance(key, ast.Constant) for key in value.keys) and all(
            _inert(element) for element in value.values
        )
    return False


def _injected_name(node: ast.expr | None) -> str:
    if node is None:
        return "an error (bare except)"
    first = node.elts[0] if isinstance(node, ast.Tuple) and node.elts else node
    return ast.unparse(first)
