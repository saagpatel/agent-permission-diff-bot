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
    source = (
        "def f():\n    try:\n        verify(token)\n    except Exception:\n        return None\n"
    )
    assert _probe(source, 4)[2] == "the caller gets `None` instead of an error"


def test_a_returned_name_is_described_and_assignments_are_followed() -> None:
    source = "def f():\n    try:\n        a()\n    except Exception:\n        return cached\n"
    assert _probe(source, 4)[2] == "the caller gets the value of `cached` instead of an error"
    chained = (
        "def f():\n    try:\n        a()\n    except Exception:\n"
        "        previous = result\n        result = None\n        return previous\n"
    )
    assert _probe(chained, 4)[2] == "the caller gets the value of `result` instead of an error"


def test_continue_and_break_in_loops() -> None:
    loop = "for x in xs:\n    try:\n        x.save()\n    except Exception:\n        {}\n"
    assert "moves on" in _probe(loop.format("continue"), 4)[2]
    assert "stops early" in _probe(loop.format("break"), 4)[2]


def test_exception_names_are_reported_as_written() -> None:
    assert _probe("try:\n    a()\nexcept requests.RequestException:\n    pass\n", 3)[1] == (
        "requests.RequestException"
    )
    assert _probe("try:\n    a()\nexcept (UnicodeDecodeError, ValueError):\n    pass\n", 3)[1] == (
        "UnicodeDecodeError"
    )
    assert _probe("try:\n    a()\nexcept:\n    pass\n", 3)[1] == "an error (bare except)"


@pytest.mark.parametrize(
    "body",
    [
        "log.exception('x')",
        "raise",
        "return [i for i in x]",
        "return (y := 1)",
        "x.y",
        "f",
        "return 1 / 0",
        "return x.y",
        "return d[k]",
        "result = -x",
        "return {**d}",
        "return f'{x}'",
    ],
)
def test_handlers_that_could_run_code_are_not_probed(body: str) -> None:
    source = f"try:\n    a()\nexcept Exception:\n    {body}\n"
    assert _probe(source, 3)[0] == "not-probed"


@pytest.mark.parametrize(
    "body",
    [
        'x.__init__.__globals__["marker"] = "changed"',
        "x.__class__.__getitem__ = y",
        "a, *b = c",
        "a, b = None",
        "self.failed = True",
        "cache[key] = None",
    ],
)
def test_assignments_it_cannot_follow_are_not_probed(body: str) -> None:
    # Unpacking can fail and attribute/subscript stores can run code; nothing is run, and
    # no outcome is claimed for these.
    source = f"try:\n    a()\nexcept Exception:\n    {body}\n"
    assert _probe(source, 3)[0] == "not-probed"


@pytest.mark.parametrize("extra", ["finally:\n    cleanup()\n", "else:\n    done()\n"])
def test_a_try_with_finally_or_else_is_not_probed(extra: str) -> None:
    source = f"try:\n    a()\nexcept OSError:\n    pass\n{extra}"
    assert _probe(source, 3)[0] == "not-probed"


def test_literal_values_are_described() -> None:
    source = "try:\n    a()\nexcept Exception:\n    return {'ok': False, 'code': -1}\n"
    assert _probe(source, 3)[2] == "the caller gets `{'ok': False, 'code': -1}` instead of an error"
    assert _probe("try:\n    a()\nexcept Exception:\n    return [x, ()]\n", 3)[0] == "vanished"


def test_chained_assignments_are_followed() -> None:
    source = (
        "def f():\n    try:\n        a()\n    except Exception:\n"
        "        result = 1\n        result = other = 2\n        return result\n"
    )
    assert _probe(source, 4)[2] == "the caller gets `2` instead of an error"


def test_the_scanner_probes_from_its_own_parse() -> None:
    source = (
        "def f():\n    try:\n        db.commit()\n    except Exception:\n        return 0\n" * 50
    )
    changed = ChangedFile("x.py", source, changed_lines_between("", source))
    findings = scan_swallowed([changed]).findings
    assert len(findings) == 50 and all("leaves no trace" in f.allows[1] for f in findings)


def test_swallowed_findings_carry_the_probe_result() -> None:
    source = "def f():\n    try:\n        db.commit()\n    except Exception:\n        return 0\n"
    changed = ChangedFile("x.py", source, changed_lines_between("", source))
    [finding] = scan_swallowed([changed]).findings
    assert "Probe: injecting `Exception` into the `try` leaves no trace" in finding.allows[1]
    assert "the caller gets `0`" in finding.allows[1]


def test_cli_probe(tmp_path: Path) -> None:
    target = tmp_path / "store.py"
    target.write_text("try:\n    save()\nexcept OSError:\n    pass\n", encoding="utf-8")
    command = [sys.executable, "-m", "agent_permission_diff_bot.cli", "probe-swallowed"]
    done = subprocess.run(
        [*command, str(target), "--line", "3"], capture_output=True, text=True, check=False
    )
    assert done.returncode == 0, done.stderr
    assert "injecting `OSError` into the `try` leaves no trace" in done.stdout


def test_cli_probe_refuses_non_utf8(tmp_path: Path) -> None:
    target = tmp_path / "bad.py"
    target.write_bytes(b"\xff\xfe")
    command = [sys.executable, "-m", "agent_permission_diff_bot.cli", "probe-swallowed"]
    done = subprocess.run(
        [*command, str(target), "--line", "1"], capture_output=True, text=True, check=False
    )
    assert done.returncode == 2 and "not UTF-8" in done.stderr
