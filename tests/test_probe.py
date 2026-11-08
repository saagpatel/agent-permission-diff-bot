from __future__ import annotations

import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from agent_permission_diff_bot.checks.probe import probe_python_handler
from agent_permission_diff_bot.checks.swallowed import (
    ChangedFile,
    changed_lines_between,
    scan_swallowed,
)


def _probe(source: str, line: int) -> tuple[str, str, str]:
    result = probe_python_handler(textwrap.dedent(source).lstrip("\n"), line)
    return result.outcome, result.injected, result.detail


def test_pass_lets_execution_continue_as_if_it_succeeded() -> None:
    source = """
    def save(path, data):
        try:
            path.write_text(data)
        except OSError:
            pass
    """
    assert _probe(source, 4) == (
        "vanished",
        "OSError",
        "execution continues after the `try` as if it had succeeded",
    )


def test_a_constant_return_shows_what_the_caller_gets() -> None:
    source = "try:\n    verify(token)\nexcept Exception:\n    return None\n"
    outcome, injected, detail = _probe(f"def f():\n{textwrap.indent(source, '    ')}", 4)
    assert (outcome, injected) == ("vanished", "Exception")
    assert detail == "the caller gets `None` instead of an error"


def test_a_returned_name_is_described_not_evaluated() -> None:
    source = "def f():\n    try:\n        a()\n    except Exception:\n        return cached\n"
    assert _probe(source, 4)[2] == "the caller gets the value of `cached` instead of an error"


def test_continue_and_break_in_loops() -> None:
    loop = "for x in xs:\n    try:\n        x.save()\n    except Exception:\n        {}\n"
    assert "moves on" in _probe(loop.format("continue"), 4)[2]
    assert "stops early" in _probe(loop.format("break"), 4)[2]


def test_flag_assignments_and_attribute_sets_run_harmlessly() -> None:
    source = "try:\n    a()\nexcept Exception:\n    self.failed = True\n    cache[key] = None\n"
    assert _probe(source, 3)[0] == "vanished"


def test_custom_and_bare_exceptions_get_stand_ins() -> None:
    assert _probe("try:\n    a()\nexcept requests.RequestException:\n    pass\n", 3)[1] == (
        "requests.RequestException"
    )
    assert _probe("try:\n    a()\nexcept:\n    pass\n", 3)[1] == "RuntimeError"


@pytest.mark.parametrize(
    "body",
    ["log.exception('x')", "raise", "return [i for i in x]", "return (y := 1)"],
)
def test_handlers_with_calls_or_raises_are_never_run(body: str) -> None:
    source = f"try:\n    a()\nexcept Exception:\n    {body}\n"
    assert _probe(source, 3)[0] == "not-probed"


def test_the_probe_runs_without_builtins() -> None:
    # A swallowing handler cannot call anything, but even a name like `open` resolves to an
    # inert stand-in in the probe, never the real builtin.
    source = "try:\n    a()\nexcept Exception:\n    return open\n"
    assert _probe(source, 3)[2] == "the caller gets the value of `open` instead of an error"


def test_swallowed_findings_carry_the_probe_result() -> None:
    source = (
        "def f():\n    try:\n        db.commit()\n    except Exception:\n        return False\n"
    )
    [finding] = scan_swallowed(
        [ChangedFile("x.py", source, changed_lines_between("", source))]
    ).findings
    assert "Probe: injecting `Exception` into the `try` left no trace" in finding.allows[1]
    assert "the caller gets `False`" in finding.allows[1]


def test_cli_probe(tmp_path: Path) -> None:
    target = tmp_path / "store.py"
    target.write_text("try:\n    save()\nexcept OSError:\n    pass\n", encoding="utf-8")
    done = subprocess.run(
        [
            sys.executable,
            "-m",
            "agent_permission_diff_bot.cli",
            "probe-swallowed",
            str(target),
            "--line",
            "3",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert done.returncode == 0, done.stderr
    assert "Injecting `OSError` into the try left no trace" in done.stdout
