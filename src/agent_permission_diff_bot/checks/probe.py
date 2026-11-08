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
    if handler is None or not _straight_line(handler):
        return ProbeResult("not-probed", detail="no call-free handler starts on that line")
    return ProbeResult("vanished", _injected_name(handler.type), _outcome(handler))


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
        if isinstance(statement, ast.Assign) and len(statement.targets) == 1:
            target = statement.targets[0]
            if isinstance(target, ast.Name):
                known[target.id] = _describe(statement.value, known)
        elif (
            isinstance(statement, ast.AnnAssign)
            and isinstance(statement.target, ast.Name)
            and statement.value is not None
        ):
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


def _injected_name(node: ast.expr | None) -> str:
    if node is None:
        return "an error (bare except)"
    first = node.elts[0] if isinstance(node, ast.Tuple) and node.elts else node
    return ast.unparse(first)
