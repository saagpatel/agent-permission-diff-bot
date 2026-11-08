"""Parse Claude Code permission rules (``Tool`` or ``Tool(specifier)``).

Matching semantics follow https://code.claude.com/docs/en/permissions:
everything before the first ``*`` is matched as written, a trailing ``:*`` is
the same as a trailing `` *``, a space before a trailing ``*`` is part of the
rule, and a rule with no ``*`` matches one exact command.
"""

from __future__ import annotations

import re
import shlex

from .model import CommandRule, Decision, Rule, Source

_RULE_RE = re.compile(r"^(?P<tool>[^()]+?)(?:\((?P<spec>.*)\))?$", re.DOTALL)


def split_words(text: str) -> tuple[str, ...]:
    """Split shell text into words, falling back to whitespace on bad quoting."""
    try:
        return tuple(shlex.split(text, posix=True))
    except ValueError:
        return tuple(text.split())


def parse_command_pattern(spec: str) -> CommandRule:
    """Reduce a Bash rule specifier to the words it fixes and what it leaves free."""
    spec = spec.strip()
    if spec.endswith(":*") and "*" not in spec[:-2]:
        spec = spec[:-2] + " *"
    if spec in ("", "*"):
        return CommandRule(shape="any", fixed=())
    star = spec.find("*")
    if star == -1:
        words = split_words(spec)
        return CommandRule(shape="exact", fixed=words, exact=words)
    head, tail = spec[:star], spec[star + 1 :]
    if head.strip() == "":
        # A leading wildcard stands in for the program itself.
        return CommandRule(shape="pattern", fixed=(), suffix=tail.strip())
    words = split_words(head)
    partial = ""
    if not head.endswith(" ") and words:
        partial = words[-1]
        words = words[:-1]
    shape = "prefix" if tail.strip() in ("", "*") or set(tail.strip()) <= {"*", " "} else "pattern"
    return CommandRule(shape=shape, fixed=words, partial=partial, suffix="" if shape == "prefix" else tail.strip())


def parse_rule(raw: str, decision: Decision, source: Source) -> Rule:
    m = _RULE_RE.match(raw.strip())
    if not m:
        return Rule(agent="claude", decision=decision, raw=raw, source=source, tool=raw.strip(), note="unparsed")
    tool = m.group("tool").strip()
    spec = m.group("spec")
    command = None
    if tool == "Bash":
        command = parse_command_pattern(spec if spec is not None else "*")
    return Rule(agent="claude", decision=decision, raw=raw, source=source, tool=tool, specifier=spec, command=command)


def parse_permissions(data: object, source: Source) -> list[Rule]:
    """Pull allow/ask/deny rules out of a parsed settings.json document."""
    if not isinstance(data, dict):
        return []
    perms = data.get("permissions")
    if not isinstance(perms, dict):
        return []
    rules: list[Rule] = []
    for decision in ("allow", "ask", "deny"):
        entries = perms.get(decision)
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if isinstance(entry, str) and entry.strip():
                rules.append(parse_rule(entry, decision, source))
    return rules


def parse_allowed_tools(value: object, source: Source) -> list[Rule]:
    """Parse a skill or command ``allowed-tools`` frontmatter value into allow rules.

    The value may be a YAML list, a comma-separated string, or a
    space-separated string. Commas and spaces inside parentheses belong to the
    rule, so splitting tracks parenthesis depth.
    """
    items: list[str] = []
    if isinstance(value, list):
        items = [str(v) for v in value]
    elif isinstance(value, str):
        items = _split_tool_list(value)
    return [parse_rule(item, "allow", source) for item in items if item.strip()]


def _split_tool_list(text: str) -> list[str]:
    text = text.strip()
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    sep_is_comma = "," in _outside_parens(text)
    out: list[str] = []
    depth = 0
    buf = ""
    for ch in text:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth = max(0, depth - 1)
        is_sep = depth == 0 and (ch == "," if sep_is_comma else ch.isspace())
        if is_sep:
            out.append(buf)
            buf = ""
        else:
            buf += ch
    out.append(buf)
    return [s.strip().strip("\"'") for s in out if s.strip().strip("\"'")]


def _outside_parens(text: str) -> str:
    depth = 0
    kept = []
    for ch in text:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth = max(0, depth - 1)
        elif depth == 0:
            kept.append(ch)
    return "".join(kept)
