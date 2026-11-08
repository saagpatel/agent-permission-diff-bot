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


CODEX = Source(agent="codex", kind="codex rules", label="r", path="r")


def _worst(raw: str) -> str:
    rule = parse_rule(raw, "allow", SOURCE)
    order = ["critical", "high", "medium", "low", "info"]
    found = [f.effective_severity for f in engine.analyze_rule(rule, load_kb())]
    return min(found, key=order.index) if found else "none"


def test_fd_exec_is_not_covered_by_the_find_safeguard() -> None:
    assert _worst("Bash(fd *)") == "critical"
    assert _worst("Bash(find *)") != "critical"


@pytest.mark.parametrize("raw", ["Bash(git -C . *)", "Bash(git -c*)", "Bash(git --no-pager *)"])
def test_global_option_prefix_still_reaches_what_git_reaches(raw: str) -> None:
    assert _worst(raw) == "critical"


def test_codex_prefix_with_a_global_option_is_rated_like_the_program() -> None:
    [rule] = parse_rules_text('prefix_rule(pattern=["git", "-C", "."], decision="allow")', CODEX)
    severities = {f.effective_severity for f in engine.analyze_rule(rule, load_kb())}
    assert "critical" in severities


def test_codex_suggestions_are_rated_as_the_prefix_rules_they_are() -> None:
    [rule] = parse_rules_text('prefix_rule(pattern=["npm"], decision="allow")', CODEX)
    kb = load_kb()
    suggestion = engine.suggest(rule, engine.analyze_rule(rule, kb), kb)
    residual = {(pin, f.effective_severity) for pin, f in suggestion.residual}
    assert ("npm test", "critical") in residual


@pytest.mark.parametrize(
    "text",
    [
        'prefix_rule(pattern=[{[]: 1}], decision="allow")',
        'prefix_rule(pattern=["a"], decision={[1]})',
        'prefix_rule(pattern=["a"])\x00',
    ],
)
def test_malformed_untrusted_rules_are_refused_not_crashing(text: str) -> None:
    with pytest.raises(RulesParseError):
        parse_rules_text(text, CODEX)


def test_rule_count_limit_per_file() -> None:
    union = ", ".join('["a", "b"]' for _ in range(8))  # 256 rules per call
    call = f'prefix_rule(pattern=[{union}], decision="allow")\n'
    with pytest.raises(RulesParseError):
        parse_rules_text(call * 8, CODEX)  # 2,048 rules
    small = ", ".join('["a", "b"]' for _ in range(4))  # 16 rules per call
    calls = f'prefix_rule(pattern=[{small}], decision="allow")\n' * 125  # 2,000 rules
    assert len(parse_rules_text(calls, CODEX)) == 2000


@pytest.mark.parametrize(
    ("raw", "worst"),
    [("Bash(gh release -R owner/repo *)", "high"), ("Bash(git submodule --quiet *)", "critical")],
)
def test_options_between_subcommand_words_do_not_hide_reach(raw: str, worst: str) -> None:
    assert _worst(raw) == worst


def test_codex_prefix_with_an_option_between_subcommands_is_rated_like_the_subcommand() -> None:
    [rule] = parse_rules_text(
        'prefix_rule(pattern=["gh", "release", "-R", "o/r"], decision="allow")', CODEX
    )
    severities = {f.effective_severity for f in engine.analyze_rule(rule, load_kb())}
    assert "high" in severities


@pytest.mark.parametrize(
    "text",
    [
        'r = prefix_rule\nr(pattern=["bash"], decision="allow")',
        'prefix_rule(**{"pattern": ["bash"], "decision": "allow"})',
        'prefix_rule(*[["bash"]])',
        'prefix_rule(pattern=("bash",), decision="allow")',
        'prefix_rule(pattern=["bash"], decision="maybe")',
        'prefix_rule(pattern=["bash"], decision="allow", sneaky=1)',
        'prefix_rule(pattern=["git", []], decision="allow")',
        f'prefix_rule(pattern=[0x{"f" * 4000}], decision="allow")',
        'for _ in range(1):\n    prefix_rule(pattern=["bash"], decision="allow")',
        'other_rule(pattern=["bash"])',
    ],
)
def test_rule_shapes_that_could_hide_an_allow_rule_refuse_the_file(text: str) -> None:
    with pytest.raises(RulesParseError):
        parse_rules_text(text, CODEX)


def test_a_plain_rules_file_with_a_docstring_and_justification_is_read() -> None:
    text = (
        '"""Project rules."""\n'
        'prefix_rule(pattern=["git", "status"], decision="allow", justification="read only")\n'
        'prefix_rule(["npm", "publish"], decision="forbidden")\n'
    )
    assert [r.specifier for r in parse_rules_text(text, CODEX)] == ["git status", "npm publish"]
