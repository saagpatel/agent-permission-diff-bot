"""Handle one pull request event: two check runs and one comment, updated in place."""

from __future__ import annotations

import logging
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, replace
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
    """The pull request an event asks us to check, or None when the event is not ours.

    A re-run of a check from a fork arrives with no ``pull_requests``; the target then has
    ``number == 0`` and its pull request is looked up by head commit (``resolve_target``).
    """
    installation = payload.get("installation") or {}
    repository = payload.get("repository") or {}
    if not installation.get("id") or not repository.get("id"):
        return None
    pull: Mapping[str, Any] | None = None
    head_sha = ""
    if event == "pull_request" and payload.get("action") in PULL_REQUEST_ACTIONS:
        pull = payload.get("pull_request")
        if pull and pull.get("state") != "open":
            return None
    elif event in {"check_run", "check_suite"} and payload.get("action") == "rerequested":
        source = payload.get(event) or {}
        if event == "check_run" and source.get("name") not in CHECK_NAMES.values():
            return None
        suite = source.get("check_suite") or {} if event == "check_run" else source
        pulls = source.get("pull_requests") or suite.get("pull_requests") or []
        pull = pulls[0] if pulls else None
        head_sha = str(source.get("head_sha") or suite.get("head_sha") or "")
        if pull is None and not head_sha:
            return None
    elif event != "pull_request":
        return None
    if not pull and not head_sha:
        return None
    owner = str(repository.get("owner", {}).get("login", ""))
    name = str(repository.get("name", ""))
    return PullTarget(
        installation_id=int(installation["id"]),
        repository_id=int(repository["id"]),
        owner=owner,
        name=name,
        number=int(pull["number"]) if pull else 0,
        base_sha=str(pull["base"]["sha"]) if pull else "",
        head_sha=str(pull["head"]["sha"]) if pull else head_sha,
    )


def resolve_target(repo: RepoClient, target: PullTarget) -> PullTarget | None:
    """Fill in the open pull request for a re-run that arrived without one."""
    if target.number:
        return target
    for pull in repo.pulls_for_commit(target.head_sha):
        if pull.get("state") == "open" and pull.get("head", {}).get("sha") == target.head_sha:
            return replace(target, number=int(pull["number"]), base_sha=str(pull["base"]["sha"]))
    return None


def run_checks(
    repo: RepoClient,
    target: PullTarget,
    *,
    app_id: str,
    guard_fail_on: Severity | None,
    swallowed_fail_on: Severity | None,
    is_current: Callable[[], bool] = lambda: True,
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
        merge_base = repo.merge_base(target.base_sha, target.head_sha)
        inputs = collect_inputs(repo, merge_base, target.head_sha, repo.pull_files(target.number))
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
        if result.crashed:
            verdict = "failure" if check == "config-guard" else "neutral"
        else:
            verdict = conclusion(result, fail_on[check])
        repo.complete_check_run(run_ids[check], verdict, render_check_output(result, ref))
        outcome.conclusions[CHECK_NAMES[check]] = verdict
    outcome.results = results
    body = render_comment(results, ref)
    outcome.comment_body = body
    if not is_current():
        # A newer push arrived while this one ran; its run owns the comment.
        outcome.comment_action = "stale"
        return outcome
    outcome.comment_action = _upsert_comment(repo, target.number, body, app_id, results)
    return outcome


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
        if not any(r.findings or r.deliberate or r.crashed for r in results):
            return "none"
        repo.create_comment(number, body)
        return "created"
    if str(existing.get("body", "")) == body:
        return "unchanged"
    repo.update_comment(int(existing["id"]), body)
    return "updated"
