"""Limits for the child processes that read pull request content."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class AnalysisLimits:
    """Deadline and memory cap for each limited child (see ``limited.run_limited``)."""

    timeout_s: float = 60.0
    memory_bytes: int = 1024 * 1024 * 1024
