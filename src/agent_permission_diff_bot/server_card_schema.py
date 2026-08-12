from __future__ import annotations

import re
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
CONTRACT_FAMILIES = (
    "mcp_registry_server_json",
    "mcp_registry_api",
    "mcp_protocol_discovery",
    "vendor_server_card",
    "malformed",
)
SCHEMA_STATUSES = ("recognized", "absent", "unknown", "invalid")
VALIDITIES = ("valid", "partial", "invalid")
GATE_MODES = ("observe", "warn", "enforce")
GATE_STATUSES = ("pass", "observe", "warn", "fail")


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
    schema = server_card_json_schema(kind)
    errors = _validate_json_value(payload, schema, "$")
    return {"valid": not errors, "errors": errors, "schema": kind}


def _validate_json_value(value: Any, schema: dict[str, Any], path: str) -> list[str]:
    errors: list[str] = []
    if "const" in schema and value != schema["const"]:
        errors.append(f"{path}: expected constant {schema['const']!r}")
    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{path}: expected one of {schema['enum']!r}")
    schema_type = schema.get("type")
    if schema_type and not _matches_json_type(value, schema_type):
        errors.append(f"{path}: expected {_type_label(schema_type)}")
        return errors
    if isinstance(value, str):
        pattern = schema.get("pattern")
        if isinstance(pattern, str) and re.search(pattern, value) is None:
            errors.append(f"{path}: value does not match {pattern!r}")
        minimum_length = schema.get("minLength")
        if isinstance(minimum_length, int) and len(value) < minimum_length:
            errors.append(f"{path}: expected at least {minimum_length} characters")
    if isinstance(value, int) and not isinstance(value, bool):
        minimum = schema.get("minimum")
        if isinstance(minimum, int | float) and value < minimum:
            errors.append(f"{path}: expected value >= {minimum}")
    if isinstance(value, list):
        minimum_items = schema.get("minItems")
        if isinstance(minimum_items, int) and len(value) < minimum_items:
            errors.append(f"{path}: expected at least {minimum_items} items")
        if schema.get("uniqueItems") is True:
            encoded = [repr(item) for item in value]
            if len(encoded) != len(set(encoded)):
                errors.append(f"{path}: expected unique items")
        item_schema = schema.get("items")
        if isinstance(item_schema, dict):
            for index, item in enumerate(value):
                errors.extend(_validate_json_value(item, item_schema, f"{path}[{index}]"))
    if isinstance(value, dict):
        errors.extend(_validate_json_object(value, schema, path))
    return errors


def _validate_json_object(value: dict[str, Any], schema: dict[str, Any], path: str) -> list[str]:
    errors: list[str] = []
    properties = schema.get("properties", {})
    for key in schema.get("required", []):
        if key not in value:
            errors.append(f"{path}: missing required property `{key}`")
    property_names = schema.get("propertyNames", {})
    if "enum" in property_names:
        allowed_names = set(property_names["enum"])
        for key in sorted(value):
            if key not in allowed_names:
                errors.append(f"{path}: unexpected property name `{key}`")
    additional = schema.get("additionalProperties", True)
    for key in sorted(value):
        item = value[key]
        item_path = f"{path}.{key}"
        if key in properties:
            errors.extend(_validate_json_value(item, properties[key], item_path))
        elif isinstance(additional, dict):
            errors.extend(_validate_json_value(item, additional, item_path))
        elif additional is False:
            errors.append(f"{path}: unexpected property `{key}`")
    return errors


def _matches_json_type(value: Any, schema_type: str | list[str]) -> bool:
    if isinstance(schema_type, list):
        return any(_matches_json_type(value, item) for item in schema_type)
    if schema_type == "array":
        return isinstance(value, list)
    if schema_type == "boolean":
        return isinstance(value, bool)
    if schema_type == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if schema_type == "null":
        return value is None
    if schema_type == "number":
        return isinstance(value, int | float) and not isinstance(value, bool)
    if schema_type == "object":
        return isinstance(value, dict)
    if schema_type == "string":
        return isinstance(value, str)
    return True


def _type_label(schema_type: str | list[str]) -> str:
    return " or ".join(schema_type) if isinstance(schema_type, list) else schema_type


def _report_schema() -> dict[str, Any]:
    provenance = _provenance_schema()
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
            "card_key": {"type": "string", "minLength": 1},
            "path": {"type": "string", "minLength": 1},
            "category": {"type": "string", "enum": sorted(RULES)},
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
    snapshot = {
        "type": "object",
        "additionalProperties": False,
        "required": ["label", "kind", "card_count", "cards"],
        "properties": {
            "label": {"type": "string"},
            "kind": {"type": "string", "enum": list(INPUT_KINDS)},
            "card_count": {"type": "integer", "minimum": 0},
            "cards": {"type": "array", "items": provenance},
        },
    }
    normalized_card = {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "key",
            "provenance",
            "contract_family",
            "schema_uri",
            "schema_status",
            "validity",
            "issues",
        ],
        "properties": {
            "key": {"type": "string", "minLength": 1},
            "provenance": provenance,
            "contract_family": {"type": "string", "enum": list(CONTRACT_FAMILIES)},
            "schema_uri": {"type": ["string", "null"]},
            "schema_status": {"type": "string", "enum": list(SCHEMA_STATUSES)},
            "validity": {"type": "string", "enum": list(VALIDITIES)},
            "issues": {"type": "array", "items": {"type": "string"}},
        },
    }
    counted_kinds = {
        "type": "object",
        "propertyNames": {"enum": list(DRIFT_KINDS)},
        "additionalProperties": {"type": "integer", "minimum": 0},
    }
    counted_categories = {
        "type": "object",
        "propertyNames": {"enum": sorted(RULES)},
        "additionalProperties": {"type": "integer", "minimum": 0},
    }
    summary = {
        "type": "object",
        "additionalProperties": False,
        "required": ["changes", "max_severity", "kinds", "categories", "unknown_changes"],
        "properties": {
            "changes": {"type": "integer", "minimum": 0},
            "max_severity": {"type": ["string", "null"], "enum": [None, *SEVERITIES]},
            "kinds": counted_kinds,
            "categories": counted_categories,
            "unknown_changes": {"type": "integer", "minimum": 0},
        },
    }
    gate = {
        "type": "object",
        "additionalProperties": False,
        "required": ["mode", "fail_on", "threshold_met", "status", "exit_code", "reason"],
        "properties": {
            "mode": {"type": "string", "enum": list(GATE_MODES)},
            "fail_on": {"type": "string", "enum": list(SEVERITIES)},
            "threshold_met": {"type": "boolean"},
            "status": {"type": "string", "enum": list(GATE_STATUSES)},
            "exit_code": {"type": "integer", "enum": [0, 2]},
            "reason": {"type": "string"},
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
            "report_id": {"type": "string", "pattern": "^mcp-drift-[0-9a-f]{20}$"},
            "safety_boundary": {"type": "string"},
            "standards": {"const": standards_contract()},
            "inputs": {
                "type": "object",
                "additionalProperties": False,
                "required": ["base", "head"],
                "properties": {"base": snapshot, "head": snapshot},
            },
            "normalized_cards": {
                "type": "object",
                "additionalProperties": False,
                "required": ["base", "head"],
                "properties": {
                    "base": {"type": "array", "items": normalized_card},
                    "head": {"type": "array", "items": normalized_card},
                },
            },
            "summary": summary,
            "changes": {"type": "array", "items": change},
            "gate": gate,
        },
    }


def _provenance_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "additionalProperties": False,
        "required": ["kind", "label", "path", "sha256"],
        "properties": {
            "kind": {"type": "string", "enum": list(INPUT_KINDS)},
            "label": {"type": "string"},
            "path": {"type": "string", "minLength": 1},
            "sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "git_ref": {"type": "string", "minLength": 1},
        },
    }


def _contract_schema() -> dict[str, Any]:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://agent-permission-diff.dev/schemas/mcp-server-card-contract-v1.json",
        "title": "MCP Server Card Drift Examiner contract v1",
        "type": "object",
        "additionalProperties": False,
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
            "contract": {"const": "MCP Server Card Drift Examiner"},
            "contract_version": {"const": CONTRACT_SCHEMA_VERSION},
            "report_schema_version": {"const": REPORT_SCHEMA_VERSION},
            "report_schema": {"const": REPORT_SCHEMA},
            "input_kinds": {"const": list(INPUT_KINDS)},
            "drift_kinds": {"const": list(DRIFT_KINDS)},
            "field_states": {"const": list(FIELD_STATES)},
            "severities": {"const": list(SEVERITIES)},
            "confidence_levels": {"const": list(CONFIDENCE)},
            "categories": {"const": sorted(RULES)},
            "standards": {"const": standards_contract()},
            "network_default": {"const": "off"},
            "credential_reads": {"const": "never"},
            "runtime_observation": {"const": "UNKNOWN"},
            "schema_exports": {"const": ["report", "contract"]},
        },
    }
