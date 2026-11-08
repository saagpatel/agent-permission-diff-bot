"""Cache helpers."""

import os


def clear(path: str) -> None:
    try:
        os.remove(path)
    except FileNotFoundError:  # swallowed: ok - already gone is the goal
        pass
