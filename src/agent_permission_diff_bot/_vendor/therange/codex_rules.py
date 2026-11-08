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
    except SyntaxError as exc:
        raise RulesParseError(f"{source.label}: not parseable as rules: {exc.msg} (line {exc.lineno})") from exc
    rules: list[Rule] = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "prefix_rule"):
            continue
        kwargs = {kw.arg: kw.value for kw in node.keywords if kw.arg}
        pattern_node = kwargs.get("pattern") or (node.args[0] if node.args else None)
        if pattern_node is None:
            continue
        try:
            pattern = ast.literal_eval(pattern_node)
            decision_raw = ast.literal_eval(kwargs["decision"]) if "decision" in kwargs else "allow"
        except ValueError as exc:
            raise RulesParseError(f"{source.label}: line {node.lineno}: non-literal rule field") from exc
        decision = _DECISIONS.get(str(decision_raw))
        if decision is None or not isinstance(pattern, list) or not pattern:
            continue
        for words in expand_pattern(pattern):
            rules.append(
                Rule(
                    agent="codex",
                    decision=decision,
                    raw=canonical(words, str(decision_raw)),
                    source=source,
                    tool="shell",
                    specifier=" ".join(words),
                    command=CommandRule(shape="prefix", fixed=words),
                )
            )
    return rules


def expand_pattern(pattern: list[object]) -> list[tuple[str, ...]]:
    """Expand union elements (``["view", "list"]``) into one word tuple each."""
    choices: list[list[str]] = []
    for element in pattern:
        if isinstance(element, (list, tuple)):
            choices.append([str(e) for e in element])
        else:
            choices.append([str(element)])
    return [tuple(combo) for combo in itertools.product(*choices)]


def canonical(words: tuple[str, ...], decision: str) -> str:
    """One-line form of a single expanded rule, for reports."""
    quoted = ", ".join(f'"{w}"' for w in words)
    return f'prefix_rule(pattern=[{quoted}], decision="{decision}")'
