"""Telling a refused source file apart from running out of memory.

CPython 3.12 and later raise ``MemoryError("Parser stack overflowed - Python source too
complex to parse")`` for source nested too deeply (a long chain of unary operators, for
example). That is a property of the file, like a ``SyntaxError``: re-running never helps,
so callers refuse the file. Any other ``MemoryError`` is treated as real exhaustion and
propagates, so a memory-capped analysis comes back unfinished. Python 3.11 raises the
overflow with no message; there it is indistinguishable from exhaustion and fails closed.
"""

from __future__ import annotations

PARSER_OVERFLOW = "too complex to parse"


def parser_overflow(exc: BaseException) -> bool:
    """Whether ``exc`` is the parser refusing over-nested source rather than exhaustion."""
    return isinstance(exc, MemoryError) and PARSER_OVERFLOW in str(exc)
