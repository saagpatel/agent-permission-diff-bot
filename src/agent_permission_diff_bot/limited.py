"""Run a parse-heavy callable in a time- and memory-limited child process.

The child is spawned fresh, so a hostile input (a YAML alias bomb, an exponential pattern)
can exhaust only the child. The timeout is enforced everywhere. The memory cap uses
``RLIMIT_AS``, which Linux enforces; macOS accepts or refuses it without enforcing it, so
there only the timeout bounds the child. Windows has no ``resource`` module; the timeout
still applies.
"""

from __future__ import annotations

import contextlib
import multiprocessing as mp
from collections.abc import Callable
from typing import Any

try:
    import resource
except ImportError:  # pragma: no cover - not POSIX
    resource = None  # type: ignore[assignment]

DEFAULT_TIMEOUT_S = 20.0
DEFAULT_MEMORY_BYTES = 1024 * 1024 * 1024


class LimitExceededError(RuntimeError):
    """The child timed out, ran out of memory, or died."""


def _child(conn: Any, fn: Callable[..., Any], args: tuple[Any, ...], memory_bytes: int) -> None:
    if resource is not None:
        # Some platforms (macOS) refuse RLIMIT_AS; the timeout still applies.
        with contextlib.suppress(ValueError, OSError):
            resource.setrlimit(resource.RLIMIT_AS, (memory_bytes, memory_bytes))
    try:
        conn.send(("ok", fn(*args)))
    except MemoryError:
        conn.send(("limit", "memory limit exceeded"))
    except Exception as exc:
        conn.send(("error", f"{type(exc).__name__}: {exc}"))
    finally:
        conn.close()


def run_limited(
    fn: Callable[..., Any],
    *args: Any,
    timeout_s: float = DEFAULT_TIMEOUT_S,
    memory_bytes: int = DEFAULT_MEMORY_BYTES,
) -> Any:
    """Call a picklable top-level ``fn`` in a spawned child; raise on limits.

    Raises ``LimitExceededError`` when the child times out, hits the memory cap, or dies
    without a result, and ``RuntimeError`` when ``fn`` itself raised.
    """
    ctx = mp.get_context("spawn")
    parent, child_conn = ctx.Pipe(duplex=False)
    proc = ctx.Process(target=_child, args=(child_conn, fn, args, memory_bytes))
    proc.start()
    child_conn.close()
    try:
        if not parent.poll(timeout_s):
            raise LimitExceededError(f"timed out after {timeout_s:g}s")
        try:
            kind, payload = parent.recv()
        except EOFError as exc:
            raise LimitExceededError("child exited without a result") from exc
    finally:
        if proc.is_alive():
            proc.kill()
        proc.join()
        parent.close()
    if kind == "ok":
        return payload
    if kind == "limit":
        raise LimitExceededError(payload)
    raise RuntimeError(payload)
