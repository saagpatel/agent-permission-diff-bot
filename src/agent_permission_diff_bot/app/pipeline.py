"""Handle one pull request event: two check runs and one comment, updated in place."""

from __future__ import annotations

import logging
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

from agent_permission_diff_bot.app.github import RepoClient
from agent_permission_diff_bot.app.snapshot import collect_inputs
from agent_permission_diff_bot.checks.config_guard import run_config_guard
from agent_permission_diff_bot.checks.model import CheckName, CheckResult
from agent_permission_diff_bot.checks.render import (
    CHECK_NAMES,
    COMMENT_MARKER,
    RepoRef,
    conclusion,
    render_check_output,
    render_comment,
)
from agent_permission_diff_bot.checks.swallowed import scan_swallowed
from agent_permission_diff_bot.model import Severity

log = logging.getLogger(__name__)

PULL_REQUEST_ACTIONS = {"opened", "synchronize", "reopened", "ready_for_review"}


@dataclass(frozen=True)
class PullTarget:
    installation_id: int
    repository_id: int
    owner: str
    name: str
    number: int
    base_sha: str
    head_sha: str


@dataclass
class RunOutcome:
    conclusions: dict[str, str] = field(default_factory=dict)
    comment_action: str = "none"  # "created", "updated", "unchanged" or "none"
    comment_body: str = ""
    results: list[CheckResult] = field(default_factory=list)


def target_from_event(event: str, payload: Mapping[str, Any]) -> PullTarget | None:
    """The pull request an event asks us to check, or None when the event is not ours."""
    installation = payload.get("installation") or {}
    repository = payload.get("repository") or {}
    if not installation.get("id") or not repository.get("id"):
        return None
    pull: Mapping[str, Any] | None = None
    if event == "pull_request" and payload.get("action") in PULL_REQUEST_ACTIONS:
        pull = payload.get("pull_request")
        if pull and pull.get("state") != "open":
            return None
    elif event == "check_run" and payload.get("action") == "rerequested":
        check_run = payload.get("check_run") or {}
        pulls = check_run.get("pull_requests") or []
        if check_run.get("name") not in CHECK_NAMES.values() or not pulls:
            return None
        pull = pulls[0]
    if not pull:
        return None
    owner = str(repository.get("owner", {}).get("login", ""))
    name = str(repository.get("name", ""))
    return PullTarget(
        installation_id=int(installation["id"]),
        repository_id=int(repository["id"]),
        owner=owner,
        name=name,
        number=int(pull["number"]),
        base_sha=str(pull["base"]["sha"]),
        head_sha=str(pull["head"]["sha"]),
    )


def run_checks(
    repo: RepoClient,
    target: PullTarget,
    *,
    app_id: str,
    guard_fail_on: Severity | None,
    swallowed_fail_on: Severity | None,
) -> RunOutcome:
    outcome = RunOutcome()
    ref = RepoRef(full_name=repo.full_name, head_sha=target.head_sha)
    run_ids: dict[CheckName, int] = {
        "config-guard": repo.create_check_run(CHECK_NAMES["config-guard"], target.head_sha),
        "swallowed": repo.create_check_run(CHECK_NAMES["swallowed"], target.head_sha),
    }
    fail_on: dict[CheckName, Severity | None] = {
        "config-guard": guard_fail_on,
        "swallowed": swallowed_fail_on,
    }
    try:
        inputs = collect_inputs(
            repo, target.base_sha, target.head_sha, repo.pull_files(target.number)
        )
        results = [
            _guarded(
                "config-guard", lambda: run_config_guard(inputs.base_files, inputs.head_files)
            ),
            _guarded("swallowed", lambda: scan_swallowed(inputs.swallowed_files)),
        ]
        results[0].notes[:0] = inputs.guard_notes
        results[1].notes[:0] = inputs.swallowed_notes
    except Exception as exc:
        log.exception("Reading pull request %s#%s failed", repo.full_name, target.number)
        _fail_runs(repo, run_ids, exc)
        raise
    for result in results:
        check = result.check
        if _crashed(result):
            verdict = "failure" if check == "config-guard" else "neutral"
        else:
            verdict = conclusion(result, fail_on[check])
        repo.complete_check_run(run_ids[check], verdict, render_check_output(result, ref))
        outcome.conclusions[CHECK_NAMES[check]] = verdict
    outcome.results = results
    body = render_comment(results, ref)
    outcome.comment_body = body
    outcome.comment_action = _upsert_comment(repo, target.number, body, app_id, results)
    return outcome


_CRASH_NOTE = "The check did not finish: "


def _guarded(name: CheckName, run: Callable[[], CheckResult]) -> CheckResult:
    """Run one check; a crash becomes a visible note instead of silently passing."""
    try:
        return run()
    except Exception as exc:
        log.exception("The %s check crashed", name)
        result = CheckResult(check=name)
        result.notes.append(f"{_CRASH_NOTE}{type(exc).__name__}. Re-run the check to retry.")
        return result


def _crashed(result: CheckResult) -> bool:
    return any(note.startswith(_CRASH_NOTE) for note in result.notes)


def _fail_runs(repo: RepoClient, run_ids: Mapping[CheckName, int], exc: Exception) -> None:
    for check, run_id in run_ids.items():
        verdict = "failure" if check == "config-guard" else "neutral"
        output = {
            "title": "The check did not finish",
            "summary": (
                f"Reading the pull request failed ({type(exc).__name__}). "
                "Re-run the check to retry."
            ),
        }
        try:
            repo.complete_check_run(run_id, verdict, output)
        except Exception:
            log.exception("Could not mark check run %s as failed", run_id)


def _upsert_comment(
    repo: RepoClient, number: int, body: str, app_id: str, results: list[CheckResult]
) -> str:
    existing = next(
        (
            comment
            for comment in repo.issue_comments(number)
            if COMMENT_MARKER in str(comment.get("body", ""))
            and str((comment.get("performed_via_github_app") or {}).get("id", "")) == app_id
        ),
        None,
    )
    if existing is None:
        if not any(r.findings or r.deliberate for r in results):
            return "none"
        repo.create_comment(number, body)
        return "created"
    if str(existing.get("body", "")) == body:
        return "unchanged"
    repo.update_comment(int(existing["id"]), body)
    return "updated"
