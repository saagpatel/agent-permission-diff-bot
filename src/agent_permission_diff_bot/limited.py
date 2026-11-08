"""Run a parse-heavy callable in a time- and memory-limited child process.

The child is spawned fresh, so a hostile input (a YAML alias bomb, an exponential pattern)
can exhaust only the child:

- One deadline covers everything: starting the child (including importing ``fn``'s module),
  running ``fn``, and receiving its whole result. Past it, the child is killed.
- The child encodes its own result and refuses one larger than ``max_result_bytes``; the
  parent never reads more than that either.
- The parent decodes the result with an unpickler that only rebuilds plain data and classes
  from this package, so decoding runs no other code.
- The memory cap uses ``RLIMIT_AS``, which Linux enforces. macOS accepts or refuses it
  without enforcing it, and Windows has no ``resource`` module; there only the deadline
  bounds the child.
"""

from __future__ import annotations

import contextlib
import io
import multiprocessing as mp
import pickle
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

_ALLOWED_PREFIX = "agent_permission_diff_bot."
_ALLOWED_BUILTINS = frozenset({"set", "frozenset", "complex", "bytearray", "range", "slice"})


class LimitExceededError(RuntimeError):
    """The child timed out, ran out of memory, returned too much, or died."""


class _PlainDataUnpickler(pickle.Unpickler):
    """Rebuild plain data and this package's own classes; refuse every other global.

    Why pickle is acceptable here: the bytes come only from the child this module spawned,
    running this package's code with the same privileges as the parent, so the child is
    not a trust boundary to defend; the hostile part is the *input* it parsed. Even so, the
    decoder resolves only top-level classes defined in this package (no dotted names, no
    functions, nothing re-exported from other modules), so a result cannot name a callable
    such as ``subprocess.run`` for unpickling to invoke.
    """

    def find_class(self, module: str, name: str) -> Any:
        if module == "builtins" and name in _ALLOWED_BUILTINS:
            return super().find_class(module, name)
        if module.startswith(_ALLOWED_PREFIX) and "." not in name:
            found = super().find_class(module, name)
            if isinstance(found, type) and found.__module__ == module:
                return found
        raise pickle.UnpicklingError(f"{module}.{name} is not allowed in a result")


def _child(
    conn: Any,
    fn: Callable[..., Any],
    args: tuple[Any, ...],
    memory_bytes: int,
    max_result_bytes: int,
) -> None:
    if resource is not None:
        with contextlib.suppress(ValueError, OSError):
            resource.setrlimit(resource.RLIMIT_AS, (memory_bytes, memory_bytes))
    try:
        try:
            message: tuple[str, Any] = ("ok", fn(*args))
        except MemoryError:
            message = ("limit", "memory limit exceeded")
        except Exception as exc:
            message = ("error", f"{type(exc).__name__}: {exc}")
        try:
            data = pickle.dumps(message, protocol=pickle.HIGHEST_PROTOCOL)
        except MemoryError:
            data = pickle.dumps(("limit", "memory limit exceeded"))
        except Exception as exc:
            data = pickle.dumps(("error", f"result could not be encoded: {type(exc).__name__}"))
        if len(data) > max_result_bytes:
            data = pickle.dumps(("limit", f"result is larger than {max_result_bytes} bytes"))
        conn.send_bytes(data)
    finally:
        conn.close()


def receive_within(conn: Any, timeout_s: float, max_bytes: int) -> bytes:
    """Read one whole message from ``conn`` before ``timeout_s`` passes, or raise.

    ``Connection.poll`` only says the first bytes have arrived, so the read runs in a
    helper thread and the deadline covers the complete transfer. On a timeout the caller
    must close the sending side (kill the child) so the helper thread can finish.
    """
    box: dict[str, Any] = {}

    def read() -> None:
        try:
            box["data"] = conn.recv_bytes(max_bytes)
        except BaseException as exc:  # reported to the caller below
            box["error"] = exc

    reader = threading.Thread(target=read, name="run-limited-receive", daemon=True)
    reader.start()
    reader.join(timeout_s)
    if reader.is_alive():
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
    """Call a picklable top-level ``fn`` in a spawned child; raise on limits.

    ``timeout_s`` includes starting the child and importing ``fn``'s module. Raises
    ``LimitExceededError`` when the deadline passes, the memory cap is hit, the result is
    too large or of a type outside this package, or the child dies without a whole result;
    and ``RuntimeError`` when ``fn`` itself raised.
    """
    ctx = mp.get_context("spawn")
    parent, child_conn = ctx.Pipe(duplex=False)
    proc = ctx.Process(target=_child, args=(child_conn, fn, args, memory_bytes, max_result_bytes))
    proc.start()
    child_conn.close()
    try:
        data = receive_within(parent, timeout_s, max_result_bytes)
    finally:
        if proc.is_alive():
            proc.kill()
        proc.join()
        parent.close()
    try:
        kind, payload = _PlainDataUnpickler(io.BytesIO(data)).load()
    except (pickle.UnpicklingError, ValueError, TypeError, EOFError) as exc:
        raise LimitExceededError(f"result could not be decoded safely: {exc}") from exc
    if kind == "ok":
        return payload
    if kind == "limit":
        raise LimitExceededError(payload)
    raise RuntimeError(payload)
