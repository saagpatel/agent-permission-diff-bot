from __future__ import annotations

from pathlib import Path

import pytest

from agent_permission_diff_bot.atomic import atomic_write_text


def test_atomic_write_preserves_previous_report_if_replace_fails(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    target = tmp_path / "report.json"
    target.write_text("previous", encoding="utf-8")

    def fail_replace(_source: Path, _target: Path) -> None:
        raise OSError("replace failed")

    monkeypatch.setattr("agent_permission_diff_bot.atomic.os.replace", fail_replace)
    with pytest.raises(OSError, match="replace failed"):
        atomic_write_text(target, "new")

    assert target.read_text(encoding="utf-8") == "previous"
    assert list(tmp_path.glob(".report.json.*")) == []
