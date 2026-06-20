from __future__ import annotations

import json
import os
from pathlib import Path

from agent_permission_diff_bot.model import PermissionDiffReport


def write_json(report: PermissionDiffReport, path: Path) -> None:
    path.write_text(
        json.dumps(report.to_dict(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def write_markdown(report: PermissionDiffReport, path: Path) -> None:
    path.write_text(render_markdown(report), encoding="utf-8")


def write_sarif(report: PermissionDiffReport, path: Path) -> None:
    path.write_text(
        json.dumps(render_sarif(report), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def append_step_summary(report: PermissionDiffReport, path: Path | None = None) -> None:
    summary_path = path or _github_step_summary_path()
    if summary_path is None:
        return
    with summary_path.open("a", encoding="utf-8") as handle:
        handle.write(render_markdown(report))
        handle.write("\n")


def render_markdown(report: PermissionDiffReport) -> str:
    lines = [
        "# Agent Permission Diff",
        "",
        f"- Base: `{report.base}`",
        f"- Head: `{report.head}`",
        f"- Findings: `{len(report.findings)}`",
        f"- Permission changes: `{len(report.changes)}`",
        "",
    ]

    if report.findings:
        lines.extend(["## Findings", ""])
        for finding in report.findings:
            lines.extend(
                [
                    f"### {finding.severity.label().upper()} {finding.rule_id}: {finding.title}",
                    "",
                    finding.summary,
                    "",
                    f"Reviewer decision: {finding.reviewer_decision}",
                    "",
                ]
            )
            if finding.evidence:
                lines.append("Evidence:")
                lines.extend(f"- {item}" for item in finding.evidence[:8])
                lines.append("")
    else:
        lines.extend(["## Findings", "", "No agent-facing permission findings.", ""])

    if report.changes:
        lines.extend(["## Permission Changes", ""])
        for change in report.changes:
            atom = change.atom
            lines.append(
                f"- `{change.kind}` `{atom.surface}` `{atom.action}` "
                f"`{atom.value}` in `{atom.path}`"
            )
        lines.append("")

    return "\n".join(lines)


def render_sarif(report: PermissionDiffReport) -> dict[str, object]:
    rules_by_id: dict[str, dict[str, object]] = {}
    results: list[dict[str, object]] = []

    for finding in report.findings:
        rules_by_id.setdefault(
            finding.rule_id,
            {
                "id": finding.rule_id,
                "name": finding.title,
                "shortDescription": {"text": finding.title},
                "fullDescription": {"text": finding.summary},
                "help": {"text": finding.reviewer_decision},
                "properties": {
                    "category": "agent-permission-diff",
                    "severity": finding.severity.label(),
                },
            },
        )
        results.append(
            {
                "ruleId": finding.rule_id,
                "level": _sarif_level(finding.severity.label()),
                "message": {"text": finding.summary},
                "locations": _finding_locations(finding),
                "properties": {
                    "confidence": finding.confidence,
                    "reviewerDecision": finding.reviewer_decision,
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
                        "name": "Agent Permission Diff Bot",
                        "informationUri": "https://github.com/saagpatel/agent-permission-diff-bot",
                        "rules": list(rules_by_id.values()),
                    }
                },
                "results": results,
            }
        ],
    }


def _finding_locations(finding: object) -> list[dict[str, object]]:
    paths = []
    for change in getattr(finding, "changes", []):
        path = change.atom.path
        if path not in paths:
            paths.append(path)

    if not paths:
        return []

    return [
        {
            "physicalLocation": {
                "artifactLocation": {"uri": path},
                "region": {"startLine": 1},
            }
        }
        for path in paths[:10]
    ]


def _sarif_level(severity: str) -> str:
    if severity in {"critical", "high"}:
        return "error"
    if severity == "medium":
        return "warning"
    return "note"


def _github_step_summary_path() -> Path | None:
    value = os.environ.get("GITHUB_STEP_SUMMARY")
    return Path(value) if value else None
