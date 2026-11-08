import os
import struct
import sys
import threading
import time
from dataclasses import dataclass
from typing import Any

import pytest
import yaml

from agent_permission_diff_bot.limited import (
    ChildStartError,
    LimitExceededError,
    call_within,
    run_limited,
)
from agent_permission_diff_bot.model import Severity

BOMB = "a: &a [x,x,x,x,x,x,x,x,x]\n" + "".join(
    f"{chr(98 + i)}: &{chr(98 + i)} [{','.join(['*' + chr(97 + i)] * 9)}]\n" for i in range(9)
)
SMALL_BOMB = "a: &a [x,x,x]\nb: &b [*a,*a,*a]\nc: [*b,*b]\n"


@dataclass
class Summary:
    name: str
    severity: Severity
    tags: tuple[str, ...]


def _double(x: int) -> int:
    return x * 2


def _echo(value: Any) -> Any:
    return value


def _summary() -> Summary:
    return Summary(name="rule", severity=Severity.HIGH, tags=("a", "b"))


def _sleep() -> None:
    time.sleep(30)


def _bomb() -> int:
    return len(str(yaml.safe_load(BOMB)))


def _small_bomb() -> Any:
    return yaml.safe_load(SMALL_BOMB)


def _fail() -> None:
    raise ValueError("bad input")


def _exit() -> None:
    os._exit(3)


def _big() -> str:
    return "x" * (2 * 1024 * 1024)


def _not_json() -> object:
    return object()


def _deep() -> Any:
    value: Any = []
    for _ in range(100_000):
        value = [value]
    return value


def _colliding_keys() -> dict[int, int]:
    modulus = sys.hash_info.modulus
    return {modulus * n: n for n in range(2_000)}


def test_returns_json_data() -> None:
    assert run_limited(_double, 21) == 42


def test_large_arguments_travel_inside_the_deadline() -> None:
    payload = "y" * (4 * 1024 * 1024)
    assert run_limited(_echo, payload, max_result_bytes=16 * 1024 * 1024) == payload


def test_dataclasses_and_enums_become_plain_data() -> None:
    assert run_limited(_summary) == {"name": "rule", "severity": 3, "tags": ["a", "b"]}


def test_timeout() -> None:
    with pytest.raises(LimitExceededError, match="timed out"):
        run_limited(_sleep, timeout_s=1)


def test_errors_in_the_callable_are_reported() -> None:
    with pytest.raises(RuntimeError, match="ValueError: bad input"):
        run_limited(_fail)


def test_a_result_that_is_not_json_data_is_an_error() -> None:
    with pytest.raises(RuntimeError, match="not JSON data"):
        run_limited(_not_json)


def test_a_child_that_dies_is_a_limit_not_a_result() -> None:
    with pytest.raises(LimitExceededError, match="without a whole result"):
        run_limited(_exit)


def test_oversized_result_is_refused() -> None:
    with pytest.raises(LimitExceededError, match="larger than"):
        run_limited(_big, max_result_bytes=1024 * 1024)


def test_deeply_nested_result_is_refused_in_the_child() -> None:
    with pytest.raises(LimitExceededError, match="nested too deeply"):
        run_limited(_deep)


def test_shared_references_do_not_survive_into_the_parent() -> None:
    result = run_limited(_small_bomb)
    first, second = result["b"][0], result["b"][1]
    assert first == second == ["x", "x", "x"]
    assert first is not second


def test_colliding_integer_keys_cannot_slow_the_parent() -> None:
    started = time.monotonic()
    result = run_limited(_colliding_keys)
    assert len(result) == 2_000
    assert all(isinstance(key, str) for key in list(result)[:5])
    assert time.monotonic() - started < 10


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


def _pipe() -> tuple[Any, Any]:
    import multiprocessing as mp

    return mp.Pipe(duplex=False)


def test_deadline_covers_a_message_that_stops_halfway_and_waits_for_the_reader() -> None:
    reader, writer = _pipe()
    os.write(writer.fileno(), struct.pack("!i", 100) + b"x" * 10)
    threads_before = threading.active_count()
    started = time.monotonic()
    with pytest.raises(LimitExceededError, match="timed out"):
        call_within(0.5, lambda: reader.recv_bytes(1000), writer.close)
    assert time.monotonic() - started < 3
    # The reader thread has finished before call_within returned, so closing is safe.
    assert threading.active_count() == threads_before
    reader.close()


def test_a_sender_that_dies_mid_message_is_a_limit() -> None:
    reader, writer = _pipe()
    os.write(writer.fileno(), struct.pack("!i", 100) + b"x" * 10)
    writer.close()
    with pytest.raises(LimitExceededError, match="without a whole result"):
        call_within(2, lambda: reader.recv_bytes(1000), lambda: None)
    reader.close()


def test_a_message_longer_than_the_cap_is_a_limit() -> None:
    reader, writer = _pipe()
    os.write(writer.fileno(), struct.pack("!i", 5000))
    with pytest.raises(LimitExceededError):
        call_within(2, lambda: reader.recv_bytes(1000), writer.close)
    writer.close()
    reader.close()


def _nested(depth: int) -> Any:
    value: Any = "]]] inside a string does not count ["
    for _ in range(depth):
        value = [value]
    return value


def test_nesting_up_to_the_cap_is_returned() -> None:
    assert run_limited(_nested, 200) == _nested(200)


def test_nesting_past_the_cap_is_refused() -> None:
    with pytest.raises(LimitExceededError, match="nested too deeply"):
        run_limited(_nested, 201)


class SlowToEncode:
    def __reduce__(self) -> Any:
        time.sleep(1.0)
        return (str, ("encoded",))


def test_encoding_the_arguments_counts_against_the_deadline() -> None:
    started = time.monotonic()
    with pytest.raises(LimitExceededError, match="timed out"):
        run_limited(_echo, SlowToEncode(), timeout_s=0.2)
    assert time.monotonic() - started < 3


def test_a_timeout_during_start_up_still_kills_the_child(monkeypatch: pytest.MonkeyPatch) -> None:
    import multiprocessing as mp
    from multiprocessing.context import SpawnProcess
    from multiprocessing.process import BaseProcess

    def slow_start(self: BaseProcess) -> None:
        time.sleep(1.0)
        BaseProcess.start(self)

    monkeypatch.setattr(SpawnProcess, "start", slow_start)
    with pytest.raises(LimitExceededError, match="timed out"):
        run_limited(_sleep, timeout_s=0.2)
    deadline = time.monotonic() + 5
    while mp.active_children() and time.monotonic() < deadline:
        time.sleep(0.05)
    assert mp.active_children() == []


def test_a_host_that_cannot_start_the_child_is_not_a_verdict(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from multiprocessing.context import SpawnProcess

    def refuse(self: object) -> None:
        raise OSError(11, "Resource temporarily unavailable")

    monkeypatch.setattr(SpawnProcess, "start", refuse)
    with pytest.raises(ChildStartError, match="could not start"):
        run_limited(_double, 1)
