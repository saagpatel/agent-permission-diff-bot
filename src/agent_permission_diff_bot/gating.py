from __future__ import annotations

from agent_permission_diff_bot.model import GateDecision, GateMode, PermissionDiffReport, Severity


def evaluate_gate(
    report: PermissionDiffReport,
    mode: GateMode,
    fail_on: Severity,
) -> GateDecision:
    max_severity = report.max_gate_severity
    threshold_met = max_severity is not None and max_severity >= fail_on

    if max_severity is None:
        if report.findings and report.acknowledged_findings:
            return GateDecision(
                mode=mode,
                fail_on=fail_on,
                threshold_met=False,
                status="pass",
                exit_code=0,
                reason="All findings were acknowledged by policy.",
            )
        return GateDecision(
            mode=mode,
            fail_on=fail_on,
            threshold_met=False,
            status="pass",
            exit_code=0,
            reason="No findings were produced.",
        )

    if mode == "observe":
        return GateDecision(
            mode=mode,
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
            mode=mode,
            fail_on=fail_on,
            threshold_met=True,
            status=status,
            exit_code=2,
            reason=f"Max severity {max_severity.label()} meets fail-on {fail_on.label()}.",
        )

    return GateDecision(
        mode=mode,
        fail_on=fail_on,
        threshold_met=False,
        status="pass",
        exit_code=0,
        reason=f"Max severity {max_severity.label()} is below fail-on {fail_on.label()}.",
    )
