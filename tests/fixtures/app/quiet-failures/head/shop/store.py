"""Order storage for the demo shop."""

import json
from pathlib import Path


def save_order(order: dict, path: Path) -> None:
    path.write_text(json.dumps(order))


def load_order(path: Path) -> dict | None:
    try:
        return json.loads(path.read_text())
    except OSError:
        return None
