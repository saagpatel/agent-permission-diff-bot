"""Run a parse-heavy callable in a time- and memory-limited child process.

The child is spawned fresh, so a hostile input (a YAML alias bomb, an exponential pattern)
can exhaust only the child:

- One deadline covers encoding the arguments, starting the child, handing it the
  arguments, running ``fn`` and receiving the whole result. Starting the child sends only
  a reference to ``fn``; the arguments travel over a separate pipe. Past the deadline the
  child is killed (as soon as it exists, if it was still starting), and the parent waits
  for its own I/O thread to finish before closing a pipe, at most ``_SHUTDOWN_GRACE_S``.
- The result crosses as JSON text no larger than ``max_result_bytes``. JSON has no shared
  references, no classes and no integer keys, so decoding it in the parent is linear in
  its size and cannot re-expand a structure the child flattened. Callers get plain data:
  dicts, lists, strings, numbers, booleans and ``None``. Dataclasses become dicts and enums
  their values.
- The memory cap uses ``RLIMIT_AS``, which Linux enforces. macOS accepts or refuses it
  without enforcing it, and Windows has no ``resource`` module; there only the deadline
  bounds the child.
"""

from __future__ import annotations

import contextlib
import dataclasses
import enum
import json
import multiprocessing as mp
import pickle
import re
import threading
from collections.abc import Callable
from typing import Any

try:
    import resource
except ImportError:  # pragma: no cover - not POSIX
    resource = None  # type: ignore[assignment]

DEFAULT_TIMEOUT_S = 20.0
DEFAULT_MEMORY_BYTES = 1024 * 1024 * 1024
DEFAULT_MAX_RESULT_BYTES = 8 * 1024 * 1024
# Deepest JSON nesting a result may have, so the parent's decoder never recurses far.
MAX_RESULT_DEPTH = 200
_JSON_ESCAPE = re.compile(r"\\.")
_JSON_PLAIN_STRING = re.compile(r'"[^"]*"')
_OPENERS = frozenset(b"[{")
_NOT_BRACKETS = bytes(c for c in range(256) if c not in b"[]{}")
# After a kill, how long the parent waits for its I/O thread to see the pipe close.
_SHUTDOWN_GRACE_S = 5.0


class LimitExceededError(RuntimeError):
    """The child timed out, ran out of memory, returned too much, or died."""


class ChildStartError(RuntimeError):
    """The host could not start the analysis process (out of processes or descriptors).

    Not a verdict on the input: callers should retry or report an infrastructure error.
    """


class _IOStillRunningError(LimitExceededError):
    """The deadline passed and the I/O thread did not stop; its pipes must stay open."""


def _to_json(value: Any) -> Any:
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return dataclasses.asdict(value)
    if isinstance(value, enum.Enum):
        return value.value
    if isinstance(value, (set, frozenset, tuple)):
        return list(value)
    raise TypeError(f"{type(value).__name__} is not JSON data")


def _encode(kind: str, payload: Any) -> bytes:
    return json.dumps({"kind": kind, "payload": payload}, default=_to_json, allow_nan=False).encode(
        "utf-8"
    )


def _json_depth(text: str) -> int:
    """Deepest bracket nesting in JSON text, ignoring brackets inside strings.

    Linear and constant-memory per character: escape pairs are dropped first, so a string
    is then just a quote, non-quotes and a quote. Neither pattern repeats a group, so the
    regex engine keeps no per-character backtracking state.
    """
    unescaped = _JSON_ESCAPE.sub("", text)
    outside_strings = _JSON_PLAIN_STRING.sub("", unescaped)
    brackets = outside_strings.encode("ascii", "ignore").translate(None, _NOT_BRACKETS)
    depth = deepest = 0
    for bracket in brackets:
        depth += 1 if bracket in _OPENERS else -1
        deepest = max(deepest, depth)
    return deepest


def _child(
    args_conn: Any,
    result_conn: Any,
    fn: Callable[..., Any],
    memory_bytes: int,
    max_result_bytes: int,
) -> None:
    if resource is not None:
        with contextlib.suppress(ValueError, OSError):
            resource.setrlimit(resource.RLIMIT_AS, (memory_bytes, memory_bytes))
    try:
        # The parent's own arguments: pickle is the trusted direction here.
        args = pickle.loads(args_conn.recv_bytes())
        args_conn.close()
        try:
            data = _encode("ok", fn(*args))
        except MemoryError:
            data = _encode("limit", "memory limit exceeded")
        except RecursionError:
            data = _encode("limit", "result is nested too deeply")
        except Exception as exc:
            data = _encode("error", f"{type(exc).__name__}: {exc}")
        if len(data) > max_result_bytes:
            data = _encode("limit", f"result is larger than {max_result_bytes} bytes")
        elif _json_depth(data.decode("utf-8")) > MAX_RESULT_DEPTH + 1:  # +1: the envelope
            data = _encode("limit", "result is nested too deeply")
        result_conn.send_bytes(data)
    finally:
        result_conn.close()


def call_within(timeout_s: float, work: Callable[[], bytes], stop: Callable[[], None]) -> bytes:
    """Run blocking pipe I/O under one deadline, without leaving it running afterwards.

    ``work`` runs in a helper thread. If it has not finished by ``timeout_s``, ``stop`` is
    called (it must make ``work``'s pending read or write fail, for example by killing the
    child) and the helper thread is joined before this returns, so no read can land on a
    file descriptor the caller closes and the OS reuses.
    """
    box: dict[str, Any] = {}

    def run() -> None:
        try:
            box["data"] = work()
        except Exception as exc:  # reported to the caller below
            box["error"] = exc

    worker = threading.Thread(target=run, name="run-limited-io", daemon=True)
    worker.start()
    worker.join(timeout_s)
    if worker.is_alive():
        stop()
        worker.join(_SHUTDOWN_GRACE_S)
        if worker.is_alive():
            raise _IOStillRunningError(
                f"timed out after {timeout_s:g}s and the child could not be stopped"
            )
        raise LimitExceededError(f"timed out after {timeout_s:g}s")
    if "error" in box:
        error = box["error"]
        if isinstance(error, (EOFError, OSError)):
            raise LimitExceededError("child exited without a whole result") from error
        raise error
    data: bytes = box["data"]
    return data


def run_limited(
    fn: Callable[..., Any],
    *args: Any,
    timeout_s: float = DEFAULT_TIMEOUT_S,
    memory_bytes: int = DEFAULT_MEMORY_BYTES,
    max_result_bytes: int = DEFAULT_MAX_RESULT_BYTES,
) -> Any:
    """Call a top-level ``fn`` in a spawned child and return its result as JSON data.

    ``fn`` must be importable by name, and its result JSON-serialisable (dataclasses and
    enums are converted). ``timeout_s`` includes starting the child. Raises
    ``LimitExceededError`` when the deadline passes, the memory cap is hit, the result is
    too large or too deeply nested, or the child dies without a whole result;
    ``ChildStartError`` when the host cannot start the child; and ``RuntimeError`` when
    ``fn`` raised or returned something that is not JSON data.
    """
    ctx = mp.get_context("spawn")
    args_reader, args_writer = ctx.Pipe(duplex=False)
    result_reader, result_writer = ctx.Pipe(duplex=False)
    proc = ctx.Process(
        target=_child,
        args=(args_reader, result_writer, fn, memory_bytes, max_result_bytes),
    )
    cancelled = threading.Event()

    def work() -> bytes:
        # Encoding the arguments and starting the child both run inside the deadline.
        arg_bytes = pickle.dumps(args, protocol=pickle.HIGHEST_PROTOCOL)
        if cancelled.is_set():
            raise LimitExceededError("timed out before the child started")
        try:
            proc.start()
        except OSError as exc:
            raise ChildStartError(f"could not start the analysis process: {exc}") from exc
        if cancelled.is_set():
            # The deadline passed while the child was starting; nobody else will kill it.
            proc.kill()
            raise LimitExceededError("timed out while the child started")
        args_reader.close()
        result_writer.close()
        args_writer.send_bytes(arg_bytes)
        args_writer.close()
        received: bytes = result_reader.recv_bytes(max_result_bytes)
        return received

    def stop() -> None:
        cancelled.set()
        if proc.pid is not None:
            proc.kill()

    io_finished = True
    try:
        data = call_within(timeout_s, work, stop)
    except _IOStillRunningError:
        # Leak the pipes rather than close a descriptor a live thread may still read.
        io_finished = False
        raise
    finally:
        if proc.pid is not None:
            if proc.is_alive():
                proc.kill()
            proc.join(_SHUTDOWN_GRACE_S)
        if io_finished:
            for conn in (args_reader, args_writer, result_reader, result_writer):
                conn.close()
    try:
        message = json.loads(data)
        kind, payload = message["kind"], message["payload"]
    except RecursionError as exc:
        raise LimitExceededError("result is nested too deeply") from exc
    except (ValueError, TypeError, KeyError) as exc:
        raise LimitExceededError("result could not be decoded") from exc
    if kind == "ok":
        return payload
    if kind == "limit":
        raise LimitExceededError(str(payload))
    raise RuntimeError(str(payload))
