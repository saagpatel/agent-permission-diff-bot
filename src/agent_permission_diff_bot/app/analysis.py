"""Run both checks in a time- and memory-limited child process.

Pull request content is hostile input: a pathological file (see the YAML merge-key case in
issue #60) could otherwise exhaust the webhook server. ``run_analysis`` runs Config Guard and
Swallowed inside ``run_limited``; if the child times out, runs out of memory, cannot start,
or returns something malformed, both checks come back as not finished, which Config Guard
reports as a failure. Nothing here touches the network or runs pull request code.
"""

from __future__ import annotations

import logging
from collections.abc import Callable

from agent_permission_diff_bot.app.limits import AnalysisLimits
from agent_permission_diff_bot.app.snapshot import PullInputs
from agent_permission_diff_bot.checks.config_guard import run_config_guard
from agent_permission_diff_bot.checks.model import CheckName, CheckResult, result_from_dict
from agent_permission_diff_bot.checks.swallowed import ChangedFile, scan_swallowed
from agent_permission_diff_bot.limited import ChildStartError, LimitExceededError, run_limited

log = logging.getLogger(__name__)

__all__ = ["AnalysisLimits", "analyze", "run_analysis"]

CHECKS: tuple[CheckName, CheckName] = ("config-guard", "swallowed")


def analyze(
    base_files: dict[str, str], head_files: dict[str, str], swallowed_files: list[ChangedFile]
) -> list[CheckResult]:
    """Both checks, each guarded so one crashing still reports the other. Runs in the child."""
    return [
        _guarded("config-guard", lambda: run_config_guard(base_files, head_files)),
        _guarded("swallowed", lambda: scan_swallowed(swallowed_files)),
    ]


def run_analysis(inputs: PullInputs, limits: AnalysisLimits) -> list[CheckResult]:
    try:
        raw = run_limited(
            analyze,
            inputs.base_files,
            inputs.head_files,
            inputs.swallowed_files,
            timeout_s=limits.timeout_s,
            memory_bytes=limits.memory_bytes,
        )
        if not isinstance(raw, list) or len(raw) != len(CHECKS):
            raise ValueError("the analysis returned an unexpected shape")
        results = [result_from_dict(item) for item in raw]
        if tuple(r.check for r in results) != CHECKS:
            raise ValueError("the analysis returned results out of order")
    except LimitExceededError as exc:
        log.warning("The analysis was stopped: %s", exc)
        results = _unfinished(f"The analysis was stopped: {exc}.")
    except ChildStartError:
        log.exception("Could not start the analysis process")
        results = _unfinished("The analysis process could not start. Re-run the check to retry.")
    except (RuntimeError, ValueError) as exc:
        log.exception("The analysis failed")
        results = _unfinished(f"The analysis failed ({type(exc).__name__}). Re-run to retry.")
    results[0].notes[:0] = inputs.guard_notes
    results[1].notes[:0] = inputs.swallowed_notes
    return results


def _unfinished(note: str) -> list[CheckResult]:
    return [CheckResult(check=name, crashed=True, notes=[note]) for name in CHECKS]


def _guarded(name: CheckName, run: Callable[[], CheckResult]) -> CheckResult:
    """Run one check; a crash becomes a visible result instead of silently passing."""
    try:
        return run()
    except Exception as exc:
        log.exception("The %s check crashed", name)
        result = CheckResult(check=name, crashed=True)
        result.notes.append(
            f"The check did not finish: {type(exc).__name__}. Re-run the check to retry."
        )
        return result
