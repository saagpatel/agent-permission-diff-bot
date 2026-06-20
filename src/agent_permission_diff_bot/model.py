from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import IntEnum
from typing import Any, Literal

DiffKind = Literal["added", "removed", "unchanged"]
GateMode = Literal["observe", "warn", "enforce"]
GateStatus = Literal["observe", "pass", "warn", "fail"]


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
class FindingAcknowledgement:
    reason: str
    paths: tuple[str, ...]
    expires: str | None = None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "reason": self.reason,
            "paths": list(self.paths),
        }
        if self.expires is not None:
            payload["expires"] = self.expires
        return payload


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
    acknowledgement: FindingAcknowledgement | None = None

    @property
    def acknowledged(self) -> bool:
        return self.acknowledgement is not None

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.label(),
            "summary": self.summary,
            "evidence": self.evidence,
            "changes": [change.to_dict() for change in self.changes],
            "confidence": self.confidence,
            "reviewer_decision": self.reviewer_decision,
            "acknowledged": self.acknowledged,
        }
        if self.acknowledgement is not None:
            payload["acknowledgement"] = self.acknowledgement.to_dict()
        return payload

    def paths(self) -> tuple[str, ...]:
        return tuple(sorted({change.atom.path for change in self.changes}))


@dataclass(frozen=True)
class GateDecision:
    mode: GateMode
    fail_on: Severity
    threshold_met: bool
    status: GateStatus
    exit_code: int
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "fail_on": self.fail_on.label(),
            "threshold_met": self.threshold_met,
            "status": self.status,
            "exit_code": self.exit_code,
            "reason": self.reason,
        }


@dataclass
class PermissionDiffReport:
    base: str
    head: str
    changes: list[PermissionChange]
    findings: list[Finding]
    gate: GateDecision | None = None

    @property
    def max_severity(self) -> Severity | None:
        if not self.findings:
            return None
        return max(finding.severity for finding in self.findings)

    @property
    def gate_findings(self) -> list[Finding]:
        return [finding for finding in self.findings if not finding.acknowledged]

    @property
    def acknowledged_findings(self) -> list[Finding]:
        return [finding for finding in self.findings if finding.acknowledged]

    @property
    def max_gate_severity(self) -> Severity | None:
        if not self.gate_findings:
            return None
        return max(finding.severity for finding in self.gate_findings)

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "base": self.base,
            "head": self.head,
            "max_severity": self.max_severity.label() if self.max_severity else None,
            "max_gate_severity": (
                self.max_gate_severity.label() if self.max_gate_severity else None
            ),
            "changes": [change.to_dict() for change in self.changes],
            "findings": [finding.to_dict() for finding in self.findings],
            "acknowledged_findings_count": len(self.acknowledged_findings),
            "gate_findings_count": len(self.gate_findings),
        }
        if self.gate is not None:
            payload["gate"] = self.gate.to_dict()
        return payload
