from __future__ import annotations

from typing import Any

from agent_permission_diff_bot.server_card_diff import RULES
from agent_permission_diff_bot.server_card_model import (
    CONTRACT_SCHEMA_VERSION,
    REPORT_SCHEMA,
    REPORT_SCHEMA_VERSION,
    standards_contract,
)

DRIFT_KINDS = ("added", "removed", "widened", "narrowed", "changed", "unknown")
FIELD_STATES = ("present", "absent", "unknown")
INPUT_KINDS = ("file", "directory", "git_ref")
SEVERITIES = ("low", "medium", "high", "critical")
CONFIDENCE = ("low", "medium", "high")


def explain_server_card_schema() -> dict[str, Any]:
    return {
        "contract": "MCP Server Card Drift Examiner",
        "contract_version": CONTRACT_SCHEMA_VERSION,
        "report_schema_version": REPORT_SCHEMA_VERSION,
        "report_schema": REPORT_SCHEMA,
        "input_kinds": list(INPUT_KINDS),
        "drift_kinds": list(DRIFT_KINDS),
        "field_states": list(FIELD_STATES),
        "severities": list(SEVERITIES),
        "confidence_levels": list(CONFIDENCE),
        "categories": sorted(RULES),
        "standards": standards_contract(),
        "network_default": "off",
        "credential_reads": "never",
        "runtime_observation": "UNKNOWN",
        "schema_exports": ["report", "contract"],
    }


def server_card_json_schema(kind: str) -> dict[str, Any]:
    schemas = {
        "report": _report_schema(),
        "contract": _contract_schema(),
    }
    if kind not in schemas:
        raise ValueError(f"unknown server-card schema kind {kind!r}")
    return schemas[kind]


def validate_server_card_json(payload: Any, kind: str) -> dict[str, Any]:
    server_card_json_schema(kind)
    errors: list[str] = []
    if kind == "contract":
        _require_object(payload, "$", errors)
        if isinstance(payload, dict):
            _require_keys(
                payload,
                {
                    "contract",
                    "contract_version",
                    "report_schema_version",
                    "report_schema",
                    "input_kinds",
                    "drift_kinds",
                    "field_states",
                    "severities",
                    "confidence_levels",
                    "categories",
                    "standards",
                    "network_default",
                    "credential_reads",
                    "runtime_observation",
                    "schema_exports",
                },
                "$",
                errors,
            )
            if payload.get("contract_version") != CONTRACT_SCHEMA_VERSION:
                errors.append("$.contract_version must equal the current contract version")
    else:
        _validate_report(payload, errors)
    return {"valid": not errors, "errors": errors, "schema": kind}


def _validate_report(payload: Any, errors: list[str]) -> None:
    _require_object(payload, "$", errors)
    if not isinstance(payload, dict):
        return
    _require_keys(
        payload,
        {
            "$schema",
            "schema_version",
            "contract_version",
            "report_id",
            "safety_boundary",
            "standards",
            "inputs",
            "normalized_cards",
            "summary",
            "changes",
            "gate",
        },
        "$",
        errors,
    )
    if payload.get("$schema") != REPORT_SCHEMA:
        errors.append("$.$schema must equal the MCP server-card drift report schema URI")
    if payload.get("schema_version") != REPORT_SCHEMA_VERSION:
        errors.append("$.schema_version must equal the current report schema version")
    if not isinstance(payload.get("report_id"), str):
        errors.append("$.report_id must be a string")
    inputs = payload.get("inputs")
    _require_object(inputs, "$.inputs", errors)
    if isinstance(inputs, dict):
        for side in ("base", "head"):
            item = inputs.get(side)
            _require_object(item, f"$.inputs.{side}", errors)
            if isinstance(item, dict):
                _require_keys(
                    item, {"label", "kind", "card_count", "cards"}, f"$.inputs.{side}", errors
                )
                if item.get("kind") not in INPUT_KINDS:
                    errors.append(f"$.inputs.{side}.kind must be a supported input kind")
    changes = payload.get("changes")
    if not isinstance(changes, list):
        errors.append("$.changes must be an array")
    else:
        for index, change in enumerate(changes):
            path = f"$.changes[{index}]"
            _require_object(change, path, errors)
            if not isinstance(change, dict):
                continue
            _require_keys(
                change,
                {
                    "rule_id",
                    "card_key",
                    "path",
                    "category",
                    "kind",
                    "severity",
                    "confidence",
                    "base",
                    "head",
                    "explanation",
                    "standard",
                    "source_contracts",
                    "locations",
                },
                path,
                errors,
            )
            if change.get("kind") not in DRIFT_KINDS:
                errors.append(f"{path}.kind must be a supported drift kind")
            if change.get("severity") not in SEVERITIES:
                errors.append(f"{path}.severity must be a supported severity")
            if change.get("confidence") not in CONFIDENCE:
                errors.append(f"{path}.confidence must be a supported confidence")
            for side in ("base", "head"):
                state = change.get(side)
                _require_object(state, f"{path}.{side}", errors)
                if isinstance(state, dict) and state.get("state") not in FIELD_STATES:
                    errors.append(f"{path}.{side}.state must be a supported field state")
    gate = payload.get("gate")
    _require_object(gate, "$.gate", errors)
    if isinstance(gate, dict):
        _require_keys(
            gate,
            {"mode", "fail_on", "threshold_met", "status", "exit_code", "reason"},
            "$.gate",
            errors,
        )


def _require_object(value: Any, path: str, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append(f"{path} must be an object")


def _require_keys(value: dict[str, Any], required: set[str], path: str, errors: list[str]) -> None:
    for key in sorted(required - set(value)):
        errors.append(f"{path}.{key} is required")


def _report_schema() -> dict[str, Any]:
    state = {
        "type": "object",
        "additionalProperties": False,
        "required": ["state", "display"],
        "properties": {
            "state": {"type": "string", "enum": list(FIELD_STATES)},
            "display": {"type": "string"},
        },
    }
    change = {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "rule_id",
            "card_key",
            "path",
            "category",
            "kind",
            "severity",
            "confidence",
            "base",
            "head",
            "explanation",
            "standard",
            "source_contracts",
            "locations",
        ],
        "properties": {
            "rule_id": {"type": "string", "pattern": "^MCP[0-9]{3}$"},
            "card_key": {"type": "string"},
            "path": {"type": "string"},
            "category": {"type": "string"},
            "kind": {"type": "string", "enum": list(DRIFT_KINDS)},
            "severity": {"type": "string", "enum": list(SEVERITIES)},
            "confidence": {"type": "string", "enum": list(CONFIDENCE)},
            "base": state,
            "head": state,
            "explanation": {"type": "string"},
            "standard": {"type": "boolean"},
            "source_contracts": {"type": "array", "items": {"type": "string"}},
            "locations": {"type": "array", "items": {"type": "string"}},
        },
    }
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": REPORT_SCHEMA,
        "title": "MCP Server Card Drift Report v1",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "$schema",
            "schema_version",
            "contract_version",
            "report_id",
            "safety_boundary",
            "standards",
            "inputs",
            "normalized_cards",
            "summary",
            "changes",
            "gate",
        ],
        "properties": {
            "$schema": {"const": REPORT_SCHEMA},
            "schema_version": {"const": REPORT_SCHEMA_VERSION},
            "contract_version": {"const": CONTRACT_SCHEMA_VERSION},
            "report_id": {"type": "string"},
            "safety_boundary": {"type": "string"},
            "standards": {"type": "object"},
            "inputs": {"type": "object"},
            "normalized_cards": {"type": "object"},
            "summary": {"type": "object"},
            "changes": {"type": "array", "items": change},
            "gate": {"type": "object"},
        },
    }


def _contract_schema() -> dict[str, Any]:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://agent-permission-diff.dev/schemas/mcp-server-card-contract-v1.json",
        "title": "MCP Server Card Drift Examiner contract v1",
        "type": "object",
        "required": [
            "contract",
            "contract_version",
            "report_schema_version",
            "report_schema",
            "input_kinds",
            "drift_kinds",
            "field_states",
            "severities",
            "confidence_levels",
            "categories",
            "standards",
            "network_default",
            "credential_reads",
            "runtime_observation",
            "schema_exports",
        ],
        "properties": {
            "contract_version": {"const": CONTRACT_SCHEMA_VERSION},
            "report_schema_version": {"const": REPORT_SCHEMA_VERSION},
            "report_schema": {"const": REPORT_SCHEMA},
        },
    }
