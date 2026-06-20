from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any

import yaml

from agent_permission_diff_bot.model import FindingAcknowledgement, PermissionDiffReport


class PolicyError(ValueError):
    pass


@dataclass(frozen=True)
class AcknowledgementRule:
    rule_id: str
    paths: tuple[str, ...]
    reason: str
    expires: date | None = None

    def is_expired(self, today: date) -> bool:
        return self.expires is not None and self.expires < today


def apply_policy_file(report: PermissionDiffReport, path: Path) -> None:
    if not path.exists():
        return
    rules = load_acknowledgements(path)
    apply_acknowledgements(report, rules)


def load_acknowledgements(path: Path, today: date | None = None) -> list[AcknowledgementRule]:
    today = today or date.today()
    payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(payload, dict):
        msg = f"{path} must contain a YAML mapping"
        raise PolicyError(msg)

    raw_acknowledgements = payload.get("acknowledgements", [])
    if raw_acknowledgements is None:
        raw_acknowledgements = []
    if not isinstance(raw_acknowledgements, list):
        msg = f"{path} acknowledgements must be a list"
        raise PolicyError(msg)

    rules: list[AcknowledgementRule] = []
    for index, item in enumerate(raw_acknowledgements, start=1):
        rule = _parse_acknowledgement(path, index, item)
        if not rule.is_expired(today):
            rules.append(rule)
    return rules


def apply_acknowledgements(
    report: PermissionDiffReport,
    rules: list[AcknowledgementRule],
) -> None:
    for finding in report.findings:
        finding_paths = set(finding.paths())
        for rule in rules:
            if finding.rule_id != rule.rule_id:
                continue
            if not finding_paths or not finding_paths.issubset(set(rule.paths)):
                continue
            finding.acknowledgement = FindingAcknowledgement(
                reason=rule.reason,
                paths=rule.paths,
                expires=rule.expires.isoformat() if rule.expires is not None else None,
            )
            break


def _parse_acknowledgement(
    path: Path,
    index: int,
    item: object,
) -> AcknowledgementRule:
    if not isinstance(item, dict):
        msg = f"{path} acknowledgement #{index} must be a mapping"
        raise PolicyError(msg)

    rule_id = _required_string(path, index, item, "rule_id")
    reason = _required_string(path, index, item, "reason")
    paths = _required_string_list(path, index, item, "paths")
    expires = _optional_date(path, index, item.get("expires"))
    return AcknowledgementRule(
        rule_id=rule_id,
        paths=tuple(paths),
        reason=reason,
        expires=expires,
    )


def _required_string(
    path: Path,
    index: int,
    item: dict[str, Any],
    key: str,
) -> str:
    value = item.get(key)
    if not isinstance(value, str) or not value.strip():
        msg = f"{path} acknowledgement #{index} requires non-empty {key}"
        raise PolicyError(msg)
    return value.strip()


def _required_string_list(
    path: Path,
    index: int,
    item: dict[str, Any],
    key: str,
) -> list[str]:
    value = item.get(key)
    if not isinstance(value, list) or not value:
        msg = f"{path} acknowledgement #{index} requires non-empty {key} list"
        raise PolicyError(msg)

    paths = []
    for raw in value:
        if not isinstance(raw, str) or not raw.strip():
            msg = f"{path} acknowledgement #{index} has invalid {key} entry"
            raise PolicyError(msg)
        paths.append(raw.strip())
    return paths


def _optional_date(path: Path, index: int, value: object) -> date | None:
    if value is None:
        return None
    if not isinstance(value, str):
        msg = f"{path} acknowledgement #{index} expires must be YYYY-MM-DD"
        raise PolicyError(msg)
    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        msg = f"{path} acknowledgement #{index} expires must be YYYY-MM-DD"
        raise PolicyError(msg) from exc
