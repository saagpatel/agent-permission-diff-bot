import sys
import time

import pytest
import yaml

from agent_permission_diff_bot.limited import LimitExceededError, run_limited

BOMB = "a: &a [x,x,x,x,x,x,x,x,x]\n" + "".join(
    f"{chr(98 + i)}: &{chr(98 + i)} [{','.join(['*' + chr(97 + i)] * 9)}]\n" for i in range(9)
)


def _double(x: int) -> int:
    return x * 2


def _sleep() -> None:
    time.sleep(30)


def _bomb() -> int:
    return len(str(yaml.safe_load(BOMB)))


def _fail() -> None:
    raise ValueError("bad input")


def _exit() -> None:
    import os

    os._exit(3)


def test_returns_result() -> None:
    assert run_limited(_double, 21) == 42


def test_timeout() -> None:
    with pytest.raises(LimitExceededError, match="timed out"):
        run_limited(_sleep, timeout_s=1)


def test_errors_in_the_callable_are_reported() -> None:
    with pytest.raises(RuntimeError, match="ValueError: bad input"):
        run_limited(_fail)


def test_a_child_that_dies_is_a_limit_not_a_result() -> None:
    with pytest.raises(LimitExceededError, match="without a result"):
        run_limited(_exit)


def test_alias_bomb_is_contained() -> None:
    # A short timeout keeps the child small on platforms that ignore the memory cap.
    with pytest.raises(LimitExceededError):
        run_limited(_bomb, timeout_s=1, memory_bytes=256 * 1024 * 1024)


@pytest.mark.skipif(sys.platform != "linux", reason="only Linux enforces RLIMIT_AS")
def test_memory_cap_stops_the_bomb_before_the_timeout() -> None:
    started = time.monotonic()
    with pytest.raises(LimitExceededError, match="memory limit exceeded"):
        run_limited(_bomb, timeout_s=30, memory_bytes=256 * 1024 * 1024)
    assert time.monotonic() - started < 30
