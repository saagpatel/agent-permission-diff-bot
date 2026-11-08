"""How parser failures on pull request content are reported (follow-ups from #72)."""

from __future__ import annotations

import ast
import inspect

import pytest

from agent_permission_diff_bot._vendor.therange import codex_rules
from agent_permission_diff_bot._vendor.therange.model import Source
from agent_permission_diff_bot.checks.swallowed import ChangedFile, scan_swallowed
from agent_permission_diff_bot.parsing import PARSER_OVERFLOW


def _python_file() -> ChangedFile:
    return ChangedFile("x.py", "try:\n    a()\nexcept Exception:\n    pass\n", frozenset({1, 2}))


@pytest.mark.parametrize(
    "failure",
    [
        ValueError("source code string cannot contain null bytes"),
        RecursionError("maximum recursion depth exceeded"),
    ],
)
def test_swallowed_notes_a_file_the_parser_refuses(
    monkeypatch: pytest.MonkeyPatch, failure: Exception
) -> None:
    def refuse(*args: object, **kwargs: object) -> object:
        raise failure

    monkeypatch.setattr(ast, "parse", refuse)
    result = scan_swallowed([_python_file()])
    assert not result.crashed and result.findings == []
    assert any("could not be parsed" in note for note in result.notes)


def test_real_memory_exhaustion_propagates_from_swallowed(monkeypatch: pytest.MonkeyPatch) -> None:
    def exhausted(*args: object, **kwargs: object) -> object:
        raise MemoryError

    monkeypatch.setattr(ast, "parse", exhausted)
    with pytest.raises(MemoryError):
        scan_swallowed([_python_file()])


def test_real_memory_exhaustion_propagates_from_the_rules_parser(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def exhausted(*args: object, **kwargs: object) -> object:
        raise MemoryError

    monkeypatch.setattr(ast, "parse", exhausted)
    source = Source(agent="codex", kind="codex rules", label="x.rules", path="x.rules")
    with pytest.raises(MemoryError):
        codex_rules.parse_rules_text("prefix_rule(pattern=['git'])\n", source)


def test_the_vendored_overflow_marker_matches_the_shared_one() -> None:
    assert f'"{PARSER_OVERFLOW}"' in inspect.getsource(codex_rules.parse_rules_text)
