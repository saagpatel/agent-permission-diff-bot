from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

from agent_permission_diff_bot.model import GateDecision, Severity

FieldState = Literal["present", "absent", "unknown"]
DriftKind = Literal["added", "removed", "widened", "narrowed", "changed", "unknown"]
ContractFamily = Literal[
    "mcp_registry_server_json",
    "mcp_registry_api",
    "mcp_protocol_discovery",
    "vendor_server_card",
    "malformed",
]

REPORT_SCHEMA = "https://agent-permission-diff.dev/schemas/mcp-server-card-drift-report-v1.json"
REPORT_SCHEMA_VERSION = "1.0.0"
CONTRACT_SCHEMA_VERSION = "1.0.0"
STANDARDS_AS_OF = "2026-08-11"
REGISTRY_COMMIT = "a25f166b4b5bee06eeecb75e4f37b2a44a8aa5be"
PROTOCOL_COMMIT = "b25c0874bf0ba699a58e21ef06f659d839659de3"
CURRENT_REGISTRY_SCHEMA = (
    "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json"
)
CURRENT_PROTOCOL_VERSION = "2026-07-28"


@dataclass(frozen=True)
class SourceProvenance:
    kind: Literal["file", "directory", "git_ref"]
    label: str
    path: str
    sha256: str
    git_ref: str | None = None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "kind": self.kind,
            "label": self.label,
            "path": self.path,
            "sha256": self.sha256,
        }
        if self.git_ref is not None:
            payload["git_ref"] = self.git_ref
        return payload


@dataclass(frozen=True)
class RawServerCard:
    provenance: SourceProvenance
    text: str


@dataclass(frozen=True)
class SourceSnapshot:
    label: str
    kind: Literal["file", "directory", "git_ref"]
    cards: tuple[RawServerCard, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "kind": self.kind,
            "card_count": len(self.cards),
            "cards": [card.provenance.to_dict() for card in self.cards],
        }


@dataclass(frozen=True)
class NormalizedField:
    path: str
    category: str
    state: FieldState
    value: Any
    display: str
    fingerprint: str
    contract: str
    standard: bool
    confidence: str
    sensitive: bool = False

    def comparison_key(self) -> tuple[str, str, str]:
        return (self.state, self.fingerprint, self.contract)


@dataclass(frozen=True)
class NormalizedServerCard:
    key: str
    provenance: SourceProvenance
    contract_family: ContractFamily
    schema_uri: str | None
    schema_status: Literal["recognized", "absent", "unknown", "invalid"]
    validity: Literal["valid", "partial", "invalid"]
    fields: tuple[NormalizedField, ...]
    issues: tuple[str, ...] = ()

    @property
    def field_map(self) -> dict[str, NormalizedField]:
        return {item.path: item for item in self.fields}

    def to_summary_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "provenance": self.provenance.to_dict(),
            "contract_family": self.contract_family,
            "schema_uri": self.schema_uri,
            "schema_status": self.schema_status,
            "validity": self.validity,
            "issues": list(self.issues),
        }


@dataclass(frozen=True)
class ServerCardChange:
    rule_id: str
    card_key: str
    path: str
    category: str
    kind: DriftKind
    severity: Severity
    confidence: str
    base_state: FieldState
    head_state: FieldState
    base_display: str
    head_display: str
    explanation: str
    standard: bool
    source_contracts: tuple[str, ...]
    locations: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "card_key": self.card_key,
            "path": self.path,
            "category": self.category,
            "kind": self.kind,
            "severity": self.severity.label(),
            "confidence": self.confidence,
            "base": {"state": self.base_state, "display": self.base_display},
            "head": {"state": self.head_state, "display": self.head_display},
            "explanation": self.explanation,
            "standard": self.standard,
            "source_contracts": list(self.source_contracts),
            "locations": list(self.locations),
        }


@dataclass
class ServerCardDriftReport:
    report_id: str
    base: SourceSnapshot
    head: SourceSnapshot
    normalized_base: tuple[NormalizedServerCard, ...]
    normalized_head: tuple[NormalizedServerCard, ...]
    changes: list[ServerCardChange]
    gate: GateDecision | None = None
    schema: str = REPORT_SCHEMA
    schema_version: str = REPORT_SCHEMA_VERSION
    contract_version: str = CONTRACT_SCHEMA_VERSION
    safety_boundary: str = (
        "Declared metadata comparison only. No network, credential, registry, server, or "
        "runtime observation was performed; observed runtime behavior remains UNKNOWN."
    )
    standards: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.standards:
            self.standards = standards_contract()

    @property
    def max_severity(self) -> Severity | None:
        return max((change.severity for change in self.changes), default=None)

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "$schema": self.schema,
            "schema_version": self.schema_version,
            "contract_version": self.contract_version,
            "report_id": self.report_id,
            "safety_boundary": self.safety_boundary,
            "standards": self.standards,
            "inputs": {
                "base": self.base.to_dict(),
                "head": self.head.to_dict(),
            },
            "normalized_cards": {
                "base": [card.to_summary_dict() for card in self.normalized_base],
                "head": [card.to_summary_dict() for card in self.normalized_head],
            },
            "summary": {
                "changes": len(self.changes),
                "max_severity": self.max_severity.label() if self.max_severity else None,
                "kinds": _count_by(self.changes, "kind"),
                "categories": _count_by(self.changes, "category"),
                "unknown_changes": sum(change.kind == "unknown" for change in self.changes),
            },
            "changes": [change.to_dict() for change in self.changes],
        }
        if self.gate is not None:
            payload["gate"] = self.gate.to_dict()
        return payload


def standards_contract() -> dict[str, Any]:
    return {
        "as_of": STANDARDS_AS_OF,
        "registry": {
            "contract": "MCP Registry server.json and Generic Registry API v0.1",
            "repository": "https://github.com/modelcontextprotocol/registry",
            "commit": REGISTRY_COMMIT,
            "server_schema": CURRENT_REGISTRY_SCHEMA,
            "draft_schema_path": "docs/reference/server-json/draft/server.schema.json",
        },
        "protocol": {
            "contract": "Model Context Protocol",
            "repository": "https://github.com/modelcontextprotocol/modelcontextprotocol",
            "commit": PROTOCOL_COMMIT,
            "version": CURRENT_PROTOCOL_VERSION,
        },
        "interpretation": {
            "standard_requirements": (
                "Registry server.json fields and Registry API wrapper metadata are interpreted "
                "only under their pinned contracts; protocol discovery fields are separately "
                "identified under the pinned MCP protocol."
            ),
            "design_inferences": (
                "Severity and widened/narrowed classifications are deterministic product policy, "
                "not MCP normative requirements."
            ),
            "vendor_extensions": (
                "Vendor aliases and unknown fields retain their original paths and are never "
                "promoted to standard claims."
            ),
        },
    }


def _count_by(changes: list[ServerCardChange], attribute: str) -> dict[str, int]:
    result: dict[str, int] = {}
    for change in changes:
        value = str(getattr(change, attribute))
        result[value] = result.get(value, 0) + 1
    return dict(sorted(result.items()))
