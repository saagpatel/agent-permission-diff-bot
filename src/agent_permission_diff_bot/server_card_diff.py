from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from typing import Any

from agent_permission_diff_bot.model import GateDecision, Severity
from agent_permission_diff_bot.server_card_model import (
    DriftKind,
    NormalizedField,
    NormalizedServerCard,
    ServerCardChange,
    ServerCardDriftReport,
    SourceSnapshot,
)
from agent_permission_diff_bot.server_card_normalize import (
    missing_field_state,
    normalize_snapshot,
)

RULES = {
    "identity": "MCP001",
    "version": "MCP002",
    "package_provenance": "MCP003",
    "transport": "MCP004",
    "authentication": "MCP005",
    "capability": "MCP006",
    "compatibility": "MCP007",
    "endpoint": "MCP008",
    "registry_metadata": "MCP009",
    "configuration": "MCP010",
    "schema": "MCP011",
    "extension": "MCP012",
    "validity": "MCP013",
    "card": "MCP014",
}
CONFIDENCE_RANK = {"low": 0, "medium": 1, "high": 2}


def build_server_card_report(
    base: SourceSnapshot,
    head: SourceSnapshot,
    *,
    mode: str = "observe",
    fail_on: Severity = Severity.CRITICAL,
) -> ServerCardDriftReport:
    normalized_base = normalize_snapshot(base)
    normalized_head = normalize_snapshot(head)
    changes: list[ServerCardChange] = []
    for base_card, head_card in _match_cards(normalized_base, normalized_head):
        if base_card is None and head_card is not None:
            changes.append(_card_presence_change(head_card, "added"))
            continue
        if head_card is None and base_card is not None:
            changes.append(_card_presence_change(base_card, "removed"))
            continue
        if base_card is None or head_card is None:
            continue
        changes.extend(_compare_card_pair(base_card, head_card))
    changes.sort(key=lambda item: (item.card_key, item.path, item.kind, item.rule_id))
    report_id = _report_id(base, head, changes)
    report = ServerCardDriftReport(
        report_id=report_id,
        base=base,
        head=head,
        normalized_base=normalized_base,
        normalized_head=normalized_head,
        changes=changes,
    )
    report.gate = evaluate_server_card_gate(report, mode, fail_on)
    return report


def evaluate_server_card_gate(
    report: ServerCardDriftReport, mode: str, fail_on: Severity
) -> GateDecision:
    max_severity = report.max_severity
    threshold_met = max_severity is not None and max_severity >= fail_on
    if max_severity is None:
        return GateDecision(
            mode=mode,  # type: ignore[arg-type]
            fail_on=fail_on,
            threshold_met=False,
            status="pass",
            exit_code=0,
            reason="No declared MCP server metadata drift was detected.",
        )
    if mode == "observe":
        return GateDecision(
            mode="observe",
            fail_on=fail_on,
            threshold_met=threshold_met,
            status="observe",
            exit_code=0,
            reason=(
                f"Max severity {max_severity.label()} is recorded but observe mode never fails."
            ),
        )
    if threshold_met:
        status = "fail" if mode == "enforce" else "warn"
        return GateDecision(
            mode=mode,  # type: ignore[arg-type]
            fail_on=fail_on,
            threshold_met=True,
            status=status,  # type: ignore[arg-type]
            exit_code=2,
            reason=f"Max severity {max_severity.label()} meets fail-on {fail_on.label()}.",
        )
    return GateDecision(
        mode=mode,  # type: ignore[arg-type]
        fail_on=fail_on,
        threshold_met=False,
        status="pass",
        exit_code=0,
        reason=f"Max severity {max_severity.label()} is below fail-on {fail_on.label()}.",
    )


def _match_cards(
    base: tuple[NormalizedServerCard, ...],
    head: tuple[NormalizedServerCard, ...],
) -> list[tuple[NormalizedServerCard | None, NormalizedServerCard | None]]:
    if len(base) == 1 and len(head) == 1:
        return [(base[0], head[0])]
    unmatched_base = list(base)
    unmatched_head = list(head)
    pairs: list[tuple[NormalizedServerCard | None, NormalizedServerCard | None]] = []
    for attribute in ("path", "key"):
        for base_card in list(unmatched_base):
            base_value = base_card.provenance.path if attribute == "path" else base_card.key
            match = next(
                (
                    card
                    for card in unmatched_head
                    if (card.provenance.path if attribute == "path" else card.key) == base_value
                ),
                None,
            )
            if match is None:
                continue
            pairs.append((base_card, match))
            unmatched_base.remove(base_card)
            unmatched_head.remove(match)
    pairs.extend((card, None) for card in unmatched_base)
    pairs.extend((None, card) for card in unmatched_head)
    return sorted(
        pairs,
        key=_pair_key,
    )


def _pair_key(
    pair: tuple[NormalizedServerCard | None, NormalizedServerCard | None],
) -> str:
    card = pair[0] or pair[1]
    return card.key if card is not None else ""


def _compare_card_pair(
    base: NormalizedServerCard, head: NormalizedServerCard
) -> list[ServerCardChange]:
    changes: list[ServerCardChange] = []
    if base.validity != head.validity or base.issues != head.issues:
        changes.append(_validity_change(base, head))
    paths = sorted(set(base.field_map) | set(head.field_map))
    for path in paths:
        base_field = base.field_map.get(path)
        head_field = head.field_map.get(path)
        if (
            base_field is not None
            and head_field is not None
            and base_field.comparison_key() == head_field.comparison_key()
        ):
            continue
        template = base_field or head_field
        if template is None:
            continue
        if base_field is None:
            base_field = _missing_field(template, base)
        if head_field is None:
            head_field = _missing_field(template, head)
        kind = _drift_kind(base_field, head_field)
        severity = _severity(template.category, path, kind, base_field, head_field)
        confidence = _confidence(base_field, head_field, kind)
        changes.append(
            ServerCardChange(
                rule_id=RULES.get(template.category, RULES["extension"]),
                card_key=head.key or base.key,
                path=path,
                category=template.category,
                kind=kind,
                severity=severity,
                confidence=confidence,
                base_state=base_field.state,
                head_state=head_field.state,
                base_display=base_field.display,
                head_display=head_field.display,
                explanation=_explanation(template.category, path, kind, base_field, head_field),
                standard=base_field.standard and head_field.standard,
                source_contracts=tuple(
                    sorted({base_field.contract, head_field.contract} - {"not_declared"})
                ),
                locations=tuple(sorted({base.provenance.path, head.provenance.path})),
            )
        )
    return changes


def _missing_field(template: NormalizedField, card: NormalizedServerCard) -> NormalizedField:
    state = missing_field_state(card)
    display = "UNKNOWN" if state == "unknown" else "ABSENT"
    return replace(
        template,
        state=state,  # type: ignore[arg-type]
        value=None,
        display=display,
        fingerprint=state,
        contract="not_declared",
        confidence="low" if state == "unknown" else template.confidence,
        sensitive=False,
    )


def _drift_kind(base: NormalizedField, head: NormalizedField) -> DriftKind:
    if "unknown" in {base.state, head.state}:
        return "unknown"
    if base.state == "absent" and head.state == "present":
        return "added"
    if base.state == "present" and head.state == "absent":
        return "removed"
    base_set = _as_set(base.value)
    head_set = _as_set(head.value)
    if base_set is not None and head_set is not None:
        if base_set < head_set:
            return "widened"
        if head_set < base_set:
            return "narrowed"
    return "changed"


def _as_set(value: Any) -> set[str] | None:
    if not isinstance(value, tuple):
        return None
    return {json.dumps(item, sort_keys=True, default=str) for item in value}


def _severity(
    category: str,
    path: str,
    kind: str,
    base: NormalizedField,
    head: NormalizedField,
) -> Severity:
    lowered = path.lower()
    if kind == "unknown":
        return Severity.MEDIUM
    if category == "authentication":
        if lowered.endswith(".is_secret") and base.value is True and head.value is False:
            return Severity.CRITICAL
        if lowered.endswith(".is_required") and base.value is True and head.value is False:
            return Severity.HIGH
        if kind in {"removed", "widened"}:
            return Severity.HIGH
        return Severity.MEDIUM
    if category == "compatibility":
        return Severity.HIGH if kind in {"narrowed", "removed"} else Severity.MEDIUM
    if category == "capability":
        return Severity.HIGH if kind in {"narrowed", "removed"} else Severity.MEDIUM
    if category == "endpoint":
        return Severity.HIGH if kind in {"added", "widened", "changed"} else Severity.MEDIUM
    if category == "transport":
        return Severity.HIGH if kind in {"removed", "narrowed", "changed"} else Severity.MEDIUM
    if category == "package_provenance":
        return Severity.HIGH if kind in {"removed", "narrowed", "changed"} else Severity.MEDIUM
    if category == "identity":
        return (
            Severity.LOW
            if any(token in lowered for token in ("title", "description", "icons"))
            else Severity.HIGH
        )
    if category == "version":
        return Severity.MEDIUM
    if category == "validity":
        return Severity.HIGH if head.value == "invalid" else Severity.MEDIUM
    if category == "card":
        return Severity.HIGH
    if category in {"registry_metadata", "schema", "configuration"}:
        return Severity.MEDIUM
    return Severity.LOW


def _confidence(base: NormalizedField, head: NormalizedField, kind: str) -> str:
    if kind == "unknown":
        return "low"
    rank = min(CONFIDENCE_RANK[base.confidence], CONFIDENCE_RANK[head.confidence])
    return next(label for label, value in CONFIDENCE_RANK.items() if value == rank)


def _explanation(
    category: str,
    path: str,
    kind: str,
    base: NormalizedField,
    head: NormalizedField,
) -> str:
    boundary = "This is declaration drift; observed runtime behavior remains UNKNOWN."
    if kind == "unknown":
        return f"The field could not be compared as absence because one side is UNKNOWN. {boundary}"
    if category == "authentication":
        if path.endswith(".is_secret") and base.value is True and head.value is False:
            return (
                "A declared secret-handling marker was removed, weakening metadata "
                f"guidance. {boundary}"
            )
        if path.endswith(".is_required") and base.value is True and head.value is False:
            return (
                "A declared authentication input became optional, weakening the "
                f"declaration. {boundary}"
            )
        if path.endswith(".is_required") and base.value is False and head.value is True:
            return (
                "A declared authentication input became required, strengthening access "
                f"requirements but potentially breaking clients. {boundary}"
            )
    phrases = {
        "added": "was newly declared",
        "removed": "is no longer declared",
        "widened": "declares a strict superset",
        "narrowed": "declares a strict subset",
        "changed": "changed value",
    }
    phrase = phrases.get(kind, "changed")
    return f"Declared {category.replace('_', ' ')} field `{path}` {phrase}. {boundary}"


def _card_presence_change(card: NormalizedServerCard, kind: str) -> ServerCardChange:
    present_head = kind == "added"
    return ServerCardChange(
        rule_id=RULES["card"],
        card_key=card.key,
        path="card",
        category="card",
        kind=kind,  # type: ignore[arg-type]
        severity=Severity.HIGH,
        confidence="high" if card.validity != "invalid" else "low",
        base_state="absent" if present_head else "present",
        head_state="present" if present_head else "absent",
        base_display="ABSENT" if present_head else card.key,
        head_display=card.key if present_head else "ABSENT",
        explanation=(
            f"An MCP server metadata declaration was {kind}. Observed runtime behavior "
            "remains UNKNOWN."
        ),
        standard=card.contract_family != "vendor_server_card",
        source_contracts=(card.contract_family,),
        locations=(card.provenance.path,),
    )


def _validity_change(base: NormalizedServerCard, head: NormalizedServerCard) -> ServerCardChange:
    kind = "unknown" if "invalid" in {base.validity, head.validity} else "changed"
    return ServerCardChange(
        rule_id=RULES["validity"],
        card_key=head.key or base.key,
        path="metadata.validity",
        category="validity",
        kind=kind,  # type: ignore[arg-type]
        severity=Severity.HIGH if head.validity == "invalid" else Severity.MEDIUM,
        confidence="low" if kind == "unknown" else "high",
        base_state="unknown" if base.validity == "invalid" else "present",
        head_state="unknown" if head.validity == "invalid" else "present",
        base_display=base.validity,
        head_display=head.validity,
        explanation=(
            "Card validity or normalization issues changed. Missing fields on an invalid or "
            "unrecognized card are UNKNOWN, not ABSENT; runtime behavior remains UNKNOWN."
        ),
        standard=False,
        source_contracts=tuple(sorted({base.contract_family, head.contract_family})),
        locations=tuple(sorted({base.provenance.path, head.provenance.path})),
    )


def _report_id(base: SourceSnapshot, head: SourceSnapshot, changes: list[ServerCardChange]) -> str:
    payload = {
        "base": [card.provenance.sha256 for card in base.cards],
        "head": [card.provenance.sha256 for card in head.cards],
        "changes": [change.to_dict() for change in changes],
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return "mcp-drift-" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()[:20]
