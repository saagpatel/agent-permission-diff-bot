"""The vendored Range engine loads its knowledge base and keeps the local safety patch."""

from __future__ import annotations

import pytest

from agent_permission_diff_bot._vendor.therange import engine
from agent_permission_diff_bot._vendor.therange.claude_rules import parse_rule
from agent_permission_diff_bot._vendor.therange.codex_rules import (
    RulesParseError,
    parse_rules_text,
)
from agent_permission_diff_bot._vendor.therange.kb import load_kb
from agent_permission_diff_bot._vendor.therange.model import Source

SOURCE = Source(agent="claude", kind="project settings", label="x", path="x")


def test_knowledge_base_ships_with_the_package() -> None:
    assert len(load_kb().capabilities) > 50


def test_broad_git_rule_reaches_program_execution() -> None:
    rule = parse_rule("Bash(git *)", "allow", SOURCE)
    severities = {f.effective_severity for f in engine.analyze_rule(rule, load_kb())}
    assert "critical" in severities


def test_pinned_rule_suggestion_is_offered() -> None:
    rule = parse_rule("Bash(git *)", "allow", SOURCE)
    kb = load_kb()
    suggestion = engine.suggest(rule, engine.analyze_rule(rule, kb), kb)
    assert "Bash(git status *)" in suggestion.text


def test_codex_union_patterns_expand_within_the_limit() -> None:
    codex = Source(agent="codex", kind="codex rules", label="r", path="r")
    rules = parse_rules_text('prefix_rule(pattern=["gh", ["pr", "run"]], decision="allow")', codex)
    assert [r.specifier for r in rules] == ["gh pr", "gh run"]


def test_exponential_codex_union_is_refused() -> None:
    codex = Source(agent="codex", kind="codex rules", label="r", path="r")
    union = ", ".join('["a", "b"]' for _ in range(40))
    with pytest.raises(RulesParseError):
        parse_rules_text(f'prefix_rule(pattern=[{union}], decision="allow")', codex)
