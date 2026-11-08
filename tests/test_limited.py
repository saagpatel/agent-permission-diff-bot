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


def test_returns_result() -> None:
    assert run_limited(_double, 21) == 42


def test_timeout() -> None:
    with pytest.raises(LimitExceededError, match="timed out"):
        run_limited(_sleep, timeout_s=1)


def test_alias_bomb_is_contained() -> None:
    with pytest.raises(LimitExceededError):
        run_limited(_bomb, timeout_s=5, memory_bytes=256 * 1024 * 1024)
