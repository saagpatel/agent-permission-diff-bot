"""Core data types shared by the parsers, the engine and the report."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

Agent = Literal["claude", "codex"]
Decision = Literal["allow", "ask", "deny"]
Severity = Literal["critical", "high", "medium", "low", "info"]
Shape = Literal["any", "prefix", "exact", "pattern"]

SEVERITY_ORDER: dict[str, int] = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass(frozen=True)
class Source:
    """Where a rule came from. `label` is what the report prints; `path` stays local."""

    agent: Agent
    kind: str  # e.g. "user settings", "project settings", "skill allowed-tools", "codex rules"
    label: str
    path: str


@dataclass(frozen=True)
class CommandRule:
    """A shell-command rule reduced to what it fixes and what it leaves free.

    `fixed` holds the whole words before the first wildcard. `partial` holds a
    word fragment glued to the wildcard (``Bash(ls*)`` gives partial ``"ls"``),
    which matches any word that starts with it. `suffix` is literal text after
    a mid-rule wildcard (``Bash(git * main)`` gives suffix ``"main"``).
    """

    shape: Shape
    fixed: tuple[str, ...]
    partial: str = ""
    suffix: str = ""
    exact: tuple[str, ...] = ()


@dataclass(frozen=True)
class Rule:
    agent: Agent
    decision: Decision
    raw: str
    source: Source
    tool: str  # "Bash", "Read", "Edit", "WebFetch", "mcp__x__y", "shell" for Codex
    specifier: str | None = None
    command: CommandRule | None = None
    note: str = ""


@dataclass
class Finding:
    capability_id: str
    severity: Severity
    title: str
    explain: str
    example: str
    narrower: str
    doc: str
    effect: str
    mitigated_by: str = ""

    @property
    def effective_severity(self) -> Severity:
        return "info" if self.mitigated_by else self.severity


@dataclass
class RuleReport:
    rule: Rule
    findings: list[Finding] = field(default_factory=list)
    suggestion: str = ""
    residual: list[tuple[str, Finding]] = field(default_factory=list)
    live: bool = True
    live_reason: str = ""

    @property
    def worst(self) -> Severity:
        sevs: list[Severity] = [f.effective_severity for f in self.findings] or ["info"]
        return min(sevs, key=lambda s: SEVERITY_ORDER[s])


@dataclass
class GateFinding:
    """A deny or ask rule that a different spelling of the same action gets past."""

    rule: Rule
    severity: Severity
    title: str
    bypass: str
    explain: str
    doc: str
    verified: str = ""


@dataclass
class Posture:
    agent: Agent
    summary: str
    allow_rules_live: bool
    detail: str
    doc: str
