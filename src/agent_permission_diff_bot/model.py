from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import IntEnum
from typing import Any, Literal

DiffKind = Literal["added", "removed", "unchanged"]


class Severity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str) -> Severity:
        normalized = value.strip().lower()
        mapping = {
            "low": cls.LOW,
            "medium": cls.MEDIUM,
            "high": cls.HIGH,
            "critical": cls.CRITICAL,
        }
        if normalized not in mapping:
            msg = f"unknown severity {value!r}"
            raise ValueError(msg)
        return mapping[normalized]

    def label(self) -> str:
        return self.name.lower()


@dataclass(frozen=True)
class PermissionAtom:
    surface: str
    actor: str
    action: str
    verb: str
    resource: str
    value: str
    path: str
    scope: str = "repo"
    trigger: str = ""
    credential_keys: tuple[str, ...] = ()
    egress_hosts: tuple[str, ...] = ()
    confidence: str = "high"
    evidence: str = ""

    def key(self) -> tuple[str, str, str, str, str, str, str]:
        return (
            self.surface,
            self.actor,
            self.action,
            self.verb,
            self.resource,
            self.scope,
            self.value,
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class PermissionChange:
    kind: DiffKind
    atom: PermissionAtom

    def to_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "atom": self.atom.to_dict()}


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: Severity
    summary: str
    evidence: list[str] = field(default_factory=list)
    changes: list[PermissionChange] = field(default_factory=list)
    confidence: str = "high"
    reviewer_decision: str = "Review whether this permission expansion is intended."

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.label(),
            "summary": self.summary,
            "evidence": self.evidence,
            "changes": [change.to_dict() for change in self.changes],
            "confidence": self.confidence,
            "reviewer_decision": self.reviewer_decision,
        }


@dataclass
class PermissionDiffReport:
    base: str
    head: str
    changes: list[PermissionChange]
    findings: list[Finding]

    @property
    def max_severity(self) -> Severity | None:
        if not self.findings:
            return None
        return max(finding.severity for finding in self.findings)

    def to_dict(self) -> dict[str, Any]:
        return {
            "base": self.base,
            "head": self.head,
            "max_severity": self.max_severity.label() if self.max_severity else None,
            "changes": [change.to_dict() for change in self.changes],
            "findings": [finding.to_dict() for finding in self.findings],
        }
