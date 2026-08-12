from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from agent_permission_diff_bot.server_card_diff import RULES
from agent_permission_diff_bot.server_card_model import ServerCardDriftReport


def render_server_card_human(report: ServerCardDriftReport) -> str:
    max_severity = report.max_severity.label() if report.max_severity else "none"
    gate = report.gate
    lines = [
        "MCP Server Card Drift Examiner",
        f"Base: {report.base.label}",
        f"Head: {report.head.label}",
        f"Changes: {len(report.changes)} (max severity: {max_severity})",
    ]
    if gate is not None:
        lines.append(f"Gate: {gate.status} (exit {gate.exit_code}, fail on {gate.fail_on.label()})")
    lines.extend(["", report.safety_boundary])
    if not report.changes:
        lines.extend(["", "No declared MCP server metadata drift detected."])
        return "\n".join(lines) + "\n"
    lines.append("")
    for change in report.changes:
        scope = "standard" if change.standard else "extension"
        lines.append(
            f"[{change.severity.label().upper()}] {change.kind} {change.path} "
            f"({scope}, confidence={change.confidence})"
        )
        lines.append(f"  {change.base_display} -> {change.head_display}")
        lines.append(f"  {change.explanation}")
    return "\n".join(lines) + "\n"


def render_server_card_markdown(report: ServerCardDriftReport) -> str:
    gate = report.gate
    max_severity = report.max_severity.label() if report.max_severity else "none"
    lines = [
        "# MCP Server Card Drift",
        "",
        f"- Base: `{report.base.label}`",
        f"- Head: `{report.head.label}`",
        f"- Report contract: `{report.schema_version}`",
        f"- Changes: `{len(report.changes)}`",
        f"- Max severity: `{max_severity}`",
    ]
    if gate is not None:
        lines.extend(
            [
                f"- Gate: `{gate.status}` in `{gate.mode}` mode",
                f"- Fail on: `{gate.fail_on.label()}`",
                f"- Exit code: `{gate.exit_code}`",
            ]
        )
    lines.extend(["", "## Safety boundary", "", report.safety_boundary, ""])
    if gate is not None:
        lines.extend(["## Gate decision", "", gate.reason, ""])
    lines.extend(["## Drift", ""])
    if not report.changes:
        lines.extend(["No declared MCP server metadata drift detected.", ""])
        return "\n".join(lines)
    lines.extend(
        [
            "| Severity | Kind | Field | Scope | Confidence | Base | Head |",
            "|---|---|---|---|---|---|---|",
        ]
    )
    for change in report.changes:
        scope = "standard" if change.standard else "extension"
        lines.append(
            "| "
            + " | ".join(
                (
                    change.severity.label(),
                    change.kind,
                    _escape_table(change.path),
                    scope,
                    change.confidence,
                    _escape_table(change.base_display),
                    _escape_table(change.head_display),
                )
            )
            + " |"
        )
    lines.append("")
    lines.extend(["## Explanations", ""])
    for change in report.changes:
        source_contracts = ", ".join(f"`{item}`" for item in change.source_contracts) or "`UNKNOWN`"
        lines.extend(
            [
                f"### {change.rule_id}: `{change.path}`",
                "",
                change.explanation,
                "",
                f"Source contract(s): {source_contracts}",
                "",
            ]
        )
    return "\n".join(lines)


def render_server_card_sarif(report: ServerCardDriftReport) -> dict[str, Any]:
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    category_by_rule = {rule: category for category, rule in RULES.items()}
    for change in report.changes:
        category = category_by_rule.get(change.rule_id, change.category)
        title = f"MCP server metadata {category.replace('_', ' ')} drift"
        rules.setdefault(
            change.rule_id,
            {
                "id": change.rule_id,
                "name": title,
                "shortDescription": {"text": title},
                "fullDescription": {
                    "text": "Declared MCP metadata drift; runtime behavior is not observed."
                },
                "properties": {
                    "category": "mcp-server-card-drift",
                    "fieldCategory": category,
                },
            },
        )
        locations = [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": path},
                    "region": {"startLine": 1},
                }
            }
            for path in change.locations[:10]
        ]
        results.append(
            {
                "ruleId": change.rule_id,
                "level": _sarif_level(change.severity.label()),
                "message": {"text": change.explanation},
                "locations": locations,
                "properties": {
                    "kind": change.kind,
                    "severity": change.severity.label(),
                    "confidence": change.confidence,
                    "field": change.path,
                    "standard": change.standard,
                    "baseState": change.base_state,
                    "headState": change.head_state,
                },
            }
        )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "MCP Server Card Drift Examiner",
                        "informationUri": (
                            "https://github.com/saagpatel/agent-permission-diff-bot"
                        ),
                        "rules": [rules[key] for key in sorted(rules)],
                    }
                },
                "results": results,
            }
        ],
    }


def write_server_card_json(report: ServerCardDriftReport, path: Path) -> None:
    _write_json(report.to_dict(), path)


def write_server_card_human(report: ServerCardDriftReport, path: Path) -> None:
    path.write_text(render_server_card_human(report), encoding="utf-8")


def write_server_card_markdown(report: ServerCardDriftReport, path: Path) -> None:
    path.write_text(render_server_card_markdown(report), encoding="utf-8")


def write_server_card_sarif(report: ServerCardDriftReport, path: Path) -> None:
    _write_json(render_server_card_sarif(report), path)


def _write_json(payload: dict[str, Any], path: Path) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _escape_table(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")


def _sarif_level(severity: str) -> str:
    if severity in {"critical", "high"}:
        return "error"
    if severity == "medium":
        return "warning"
    return "note"
