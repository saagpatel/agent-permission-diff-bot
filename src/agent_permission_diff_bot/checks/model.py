"""Findings shared by the pull request checks (Config Guard and Swallowed)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Literal

from agent_permission_diff_bot.model import Severity
from agent_permission_diff_bot.redaction import redact_text

CheckName = Literal["config-guard", "swallowed"]


@dataclass(frozen=True)
class CheckFinding:
    """One ranked finding, written for the person reviewing the pull request.

    ``title`` names the change, ``allows`` says what it now lets happen (most
    important first), and ``fix`` is one suggested change. ``line`` is a 1-based
    line in the head version of ``path`` when it is known.
    """

    check: CheckName
    rule_id: str
    severity: Severity
    title: str
    path: str
    allows: tuple[str, ...]
    fix: str
    line: int | None = None
    category: str = ""


@dataclass(frozen=True)
class DeliberateCatch:
    """A swallowed error the author marked as deliberate, with their reason."""

    path: str
    line: int
    reason: str


@dataclass
class CheckResult:
    check: CheckName
    findings: list[CheckFinding] = field(default_factory=list)
    deliberate: list[DeliberateCatch] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    crashed: bool = False

    @property
    def max_severity(self) -> Severity | None:
        return max((f.severity for f in self.findings), default=None)


def rank(findings: list[CheckFinding]) -> list[CheckFinding]:
    """Most severe first; ties keep category order, then path and line."""
    return sorted(
        findings,
        key=lambda f: (-int(f.severity), _CATEGORY_ORDER.get(f.category, 9), f.path, f.line or 0),
    )


_CATEGORY_ORDER = {"auth": 0, "data-loss": 1, "network": 2, "other": 3}


def md_code(value: str) -> str:
    """``value`` as one Markdown code span, whatever backticks it contains.

    The fence is one backtick longer than the longest run inside the value, so a value
    from the pull request cannot close the span early and turn the rest into HTML.
    Credential-looking values are redacted here, before the fence is chosen, so a later
    redaction can never eat a closing backtick.
    """
    value = " ".join(redact_text(value).split()) or " "
    longest = max((len(run) for run in re.findall(r"`+", value)), default=0)
    fence = "`" * (longest + 1)
    pad = " " if value.startswith("`") or value.endswith("`") else ""
    return f"{fence}{pad}{value}{pad}{fence}"
