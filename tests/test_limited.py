import os
import struct
import sys
import time
from typing import Any

import pytest
import yaml

from agent_permission_diff_bot.limited import LimitExceededError, receive_within, run_limited

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
    with pytest.raises(LimitExceededError, match="without a whole result"):
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


def _big() -> str:
    return "x" * (2 * 1024 * 1024)


def _foreign_type() -> object:
    import datetime

    return datetime.date(2026, 1, 1)


def _package_type() -> object:
    from agent_permission_diff_bot.model import Severity

    return Severity.HIGH


def _pipe() -> tuple[Any, Any]:
    import multiprocessing as mp

    return mp.Pipe(duplex=False)


def test_oversized_result_is_refused() -> None:
    with pytest.raises(LimitExceededError, match="larger than"):
        run_limited(_big, max_result_bytes=1024 * 1024)


def test_results_outside_this_package_are_not_rebuilt() -> None:
    with pytest.raises(LimitExceededError, match="decoded safely"):
        run_limited(_foreign_type)


def test_this_packages_types_round_trip() -> None:
    from agent_permission_diff_bot.model import Severity

    assert run_limited(_package_type) is Severity.HIGH


def test_deadline_covers_a_message_that_stops_halfway() -> None:
    reader, writer = _pipe()
    os.write(writer.fileno(), struct.pack("!i", 100) + b"x" * 10)
    started = time.monotonic()
    with pytest.raises(LimitExceededError, match="timed out"):
        receive_within(reader, 0.5, 1000)
    assert time.monotonic() - started < 2
    writer.close()
    reader.close()


def test_a_sender_that_dies_mid_message_is_a_limit() -> None:
    reader, writer = _pipe()
    os.write(writer.fileno(), struct.pack("!i", 100) + b"x" * 10)
    writer.close()
    with pytest.raises(LimitExceededError, match="without a whole result"):
        receive_within(reader, 2, 1000)
    reader.close()


def test_a_message_longer_than_the_cap_is_a_limit() -> None:
    reader, writer = _pipe()
    os.write(writer.fileno(), struct.pack("!i", 5000))
    with pytest.raises(LimitExceededError):
        receive_within(reader, 2, 1000)
    writer.close()
    reader.close()
