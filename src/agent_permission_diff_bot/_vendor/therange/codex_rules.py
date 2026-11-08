"""Parse Codex command rules (``prefix_rule(...)`` calls in ``.rules`` files).

Rules files are Starlark. The ``prefix_rule`` calls use Python-compatible
syntax, so they are read with :mod:`ast` and literal evaluation only; nothing
in the file is executed. Format reference:
https://learn.chatgpt.com/docs/agent-configuration/rules
"""

from __future__ import annotations

import ast
import itertools

from .model import CommandRule, Decision, Rule, Source

_DECISIONS: dict[str, Decision] = {"allow": "allow", "prompt": "ask", "forbidden": "deny"}


class RulesParseError(ValueError):
    pass


def parse_rules_text(text: str, source: Source) -> list[Rule]:
    try:
        tree = ast.parse(text, filename=source.label)
    except (SyntaxError, ValueError, RecursionError) as exc:
        raise RulesParseError(f"{source.label}: not parseable as rules: {getattr(exc, 'msg', type(exc).__name__)} (line {getattr(exc, 'lineno', '?')})") from exc
    except MemoryError as exc:
        # Local patch: CPython's parser raises MemoryError for over-nested source; that
        # refuses the file. Any other MemoryError is exhaustion and propagates.
        if "too complex to parse" not in str(exc):
            raise
        raise RulesParseError(f"{source.label}: not parseable as rules: nested too deeply") from exc
    rules: list[Rule] = []
    # Local patch: rules files can come from pull requests, and Codex reads them as
    # Starlark, so any shape this parser skipped could hide an allow rule. Only plain
    # top-level `prefix_rule(...)` calls with literal arguments are accepted; anything
    # else (assignments, aliases, `**kwargs`, loops, other calls) refuses the whole file.
    for statement in tree.body:
        if isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Constant):
            continue  # a docstring or bare string
        node = statement.value if isinstance(statement, ast.Expr) else None
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "prefix_rule"):
            raise RulesParseError(f"{source.label}: line {statement.lineno}: only prefix_rule(...) calls are read")
        rules.extend(_rules_from_call(node, source, len(rules)))
    return rules


_KEYWORDS = {"pattern", "decision", "justification", "match", "not_match"}


def _rules_from_call(node: ast.Call, source: Source, already: int) -> list[Rule]:
    where = f"{source.label}: line {node.lineno}"
    if any(isinstance(arg, ast.Starred) for arg in node.args) or any(kw.arg is None for kw in node.keywords):
        raise RulesParseError(f"{where}: unpacked arguments are not read")
    names = [kw.arg for kw in node.keywords]
    if len(node.args) > 1 or set(names) - _KEYWORDS or len(names) != len(set(names)):
        raise RulesParseError(f"{where}: unexpected prefix_rule arguments")
    kwargs = {kw.arg: kw.value for kw in node.keywords}
    pattern_node = kwargs.get("pattern") or (node.args[0] if node.args else None)
    if pattern_node is None or ("pattern" in kwargs and node.args):
        raise RulesParseError(f"{where}: prefix_rule needs exactly one pattern")
    # Every argument must be a literal: Codex evaluates the file as Starlark, so a call
    # nested in any argument (even `justification`) would register a rule unseen here.
    try:
        pattern = ast.literal_eval(pattern_node)
        decision_raw = ast.literal_eval(kwargs["decision"]) if "decision" in kwargs else "allow"
        extras = {key: ast.literal_eval(kwargs[key]) for key in ("justification", "match", "not_match") if key in kwargs}
    except (ValueError, TypeError, SyntaxError, RecursionError) as exc:
        raise RulesParseError(f"{where}: non-literal rule field") from exc
    if "justification" in extras and not isinstance(extras["justification"], str):
        raise RulesParseError(f"{where}: justification must be a string")
    for key in ("match", "not_match"):
        if key in extras and not (
            isinstance(extras[key], list)
            and all(isinstance(e, str) or (isinstance(e, list) and all(isinstance(w, str) for w in e)) for e in extras[key])
        ):
            raise RulesParseError(f"{where}: {key} must be a list of strings or lists of strings")
    if not isinstance(decision_raw, str) or decision_raw not in _DECISIONS:
        raise RulesParseError(f"{where}: unknown decision")
    if not isinstance(pattern, list) or not pattern or not all(
        isinstance(element, str)
        or (isinstance(element, list) and element and all(isinstance(e, str) for e in element))
        for element in pattern
    ):
        raise RulesParseError(f"{where}: a pattern is a list of words or non-empty lists of words")
    decision = _DECISIONS[decision_raw]
    rules: list[Rule] = []
    for words in expand_pattern(pattern):
        if already + len(rules) >= MAX_RULES_PER_FILE:
            raise RulesParseError(f"{source.label}: more than {MAX_RULES_PER_FILE} rules")
        rules.append(
            Rule(
                agent="codex",
                decision=decision,
                raw=canonical(words, decision_raw),
                source=source,
                tool="shell",
                specifier=" ".join(words),
                command=CommandRule(shape="prefix", fixed=words),
            )
        )
    return rules


# Local patch: untrusted rules files (pull requests) must not be able to ask for an
# exponential expansion. Past these limits the file is refused, never partly expanded.
MAX_EXPANSIONS_PER_PATTERN = 256
MAX_RULES_PER_FILE = 2000


def expand_pattern(pattern: list[object]) -> list[tuple[str, ...]]:
    """Expand union elements (``["view", "list"]``) into one word tuple each."""
    choices: list[list[str]] = []
    total = 1
    for element in pattern:
        if isinstance(element, (list, tuple)):
            choices.append([str(e) for e in element])
        else:
            choices.append([str(element)])
        total *= max(len(choices[-1]), 1)
        if total > MAX_EXPANSIONS_PER_PATTERN:
            raise RulesParseError(
                f"a pattern expands to more than {MAX_EXPANSIONS_PER_PATTERN} commands"
            )
    return [tuple(combo) for combo in itertools.product(*choices)]


def canonical(words: tuple[str, ...], decision: str) -> str:
    """One-line form of a single expanded rule, for reports."""
    quoted = ", ".join(f'"{w}"' for w in words)
    return f'prefix_rule(pattern=[{quoted}], decision="{decision}")'
