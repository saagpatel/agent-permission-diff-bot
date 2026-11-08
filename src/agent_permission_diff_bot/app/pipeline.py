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
    comment_action: str = "none"  # "created", "updated", "unchanged", "stale" or "none"
    comment_body: str = ""
    results: list[CheckResult] = field(default_factory=list)


class PayloadError(ValueError):
    """A signed webhook whose payload is not shaped the way GitHub sends it."""


def target_from_event(event: str, payload: Mapping[str, Any]) -> PullTarget | None:
    """The pull request an event asks us to check, or None when the event is not ours.

    Raises ``PayloadError`` for a payload of a handled event that is missing the fields
    GitHub always sends, so the server can answer 400 instead of failing.

    - ``pull_request`` opened, pushed to, reopened or marked ready; and ``edited`` when the
      base branch changed, because the same head can widen permissions against a new base
      while its old check run still says it passed.
    - ``check_run`` / ``check_suite`` re-runs, for the commit whose check was re-run. A
      re-run from a fork arrives with no ``pull_requests``; the target then has
      ``number == 0`` and its pull request is looked up by that commit (``resolve_target``).
    """
    installation = payload.get("installation") or {}
    repository = payload.get("repository") or {}
    if not isinstance(installation, Mapping) or not isinstance(repository, Mapping):
        raise PayloadError("installation and repository must be objects")
    if not installation.get("id") or not repository.get("id"):
        return None
    pull: Any = None
    head_sha = ""
    action = payload.get("action")
    if event == "pull_request":
        changes = payload.get("changes") or {}
        retargeted = action == "edited" and isinstance(changes, Mapping) and "base" in changes
        if action not in PULL_REQUEST_ACTIONS and not retargeted:
            return None
        pull = payload.get("pull_request")
        if not isinstance(pull, Mapping):
            raise PayloadError("pull_request must be an object")
        if pull.get("state") != "open":
            return None
    elif event in {"check_run", "check_suite"} and action == "rerequested":
        source = payload.get(event)
        if not isinstance(source, Mapping):
            raise PayloadError(f"{event} must be an object")
        if event == "check_run" and source.get("name") not in CHECK_NAMES.values():
            return None
        suite = (source.get("check_suite") or {}) if event == "check_run" else source
        pulls = source.get("pull_requests") or suite.get("pull_requests") or []
        pull = pulls[0] if isinstance(pulls, list) and pulls else None
        # The commit whose check was clicked, not whatever the pull request points at now.
        head_sha = str(source.get("head_sha") or suite.get("head_sha") or "")
        if pull is None and not head_sha:
            return None
    else:
        return None
    owner = repository.get("owner") or {}
    try:
        return PullTarget(
            installation_id=int(installation["id"]),
            repository_id=int(repository["id"]),
            owner=str(owner.get("login", "")) if isinstance(owner, Mapping) else "",
            name=str(repository.get("name", "")),
            number=int(pull["number"]) if pull else 0,
            base_sha=str(pull["base"]["sha"]) if pull else "",
            head_sha=head_sha or str(pull["head"]["sha"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise PayloadError(f"pull request fields are missing or malformed: {exc}") from exc


def resolve_target(repo: RepoClient, target: PullTarget) -> PullTarget | None:
    """Fill in the open pull request for a re-run that arrived without one.

    GitHub's commit-to-pull-request lookup can come back empty for a commit that only
    exists in a fork, so the open pull requests are searched by head commit as well.
    """
    if target.number:
        return target
    for candidates in (
        lambda: repo.pulls_for_commit(target.head_sha),
        lambda: repo.open_pulls(),
    ):
        for pull in candidates():
            if pull.get("state") == "open" and pull.get("head", {}).get("sha") == target.head_sha:
                return replace(
                    target, number=int(pull["number"]), base_sha=str(pull["base"]["sha"])
                )
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
    run_ids: dict[CheckName, int] = {}
    try:
        checks: tuple[CheckName, ...] = ("config-guard", "swallowed")
        for check in checks:
            run_ids[check] = repo.create_check_run(CHECK_NAMES[check], target.head_sha)
    except Exception as exc:
        # Never leave a run that was created stuck "in progress".
        _fail_runs(repo, run_ids, exc)
        raise
    fail_on: dict[CheckName, Severity | None] = {
        "config-guard": guard_fail_on,
        "swallowed": swallowed_fail_on,
    }
    try:
        # The comparison is fixed to these commits, unlike the PR's live file list, so a late
        # webhook for an older push checks exactly that push.
        merge_base, files, truncated = repo.compare(target.base_sha, target.head_sha)
        inputs = collect_inputs(repo, merge_base, target.head_sha, files, files_truncated=truncated)
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
        _report_unfinished(repo, target, ref, app_id, is_current, exc)
        raise
    completed: set[CheckName] = set()
    try:
        for result in results:
            check = result.check
            if result.crashed:
                verdict = "failure" if check == "config-guard" else "neutral"
            else:
                verdict = conclusion(result, fail_on[check])
            repo.complete_check_run(run_ids[check], verdict, render_check_output(result, ref))
            completed.add(check)
            outcome.conclusions[CHECK_NAMES[check]] = verdict
    except Exception as exc:
        # Whatever failed to complete is marked failed, so nothing stays "in progress".
        log.exception("Completing check runs for %s#%s failed", repo.full_name, target.number)
        _fail_runs(repo, {c: i for c, i in run_ids.items() if c not in completed}, exc)
        raise
    outcome.results = results
    body = render_comment(results, ref)
    outcome.comment_body = body
    if not _still_current(is_current):
        # A newer push arrived while this one ran; its run owns the comment.
        outcome.comment_action = "stale"
        return outcome
    outcome.comment_action = _upsert_comment(repo, target.number, body, app_id, results)
    return outcome


def _still_current(is_current: Callable[[], bool]) -> bool:
    """Whether this run's head is still the pull request's head.

    If GitHub cannot say, the comment is written anyway: it names the commit it describes,
    and a newer run (serialized behind this one) rewrites it, whereas skipping would leave
    an older result standing next to these check runs.
    """
    try:
        return is_current()
    except Exception:
        log.exception("Could not read the pull request's head; writing the comment anyway")
        return True


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


def _report_unfinished(
    repo: RepoClient,
    target: PullTarget,
    ref: RepoRef,
    app_id: str,
    is_current: Callable[[], bool],
    exc: Exception,
) -> None:
    """After a read failure, the comment must not keep showing an older all-clear."""
    note = f"The check did not finish: {type(exc).__name__}. Re-run the check to retry."
    results = [
        CheckResult(check="config-guard", crashed=True, notes=[note]),
        CheckResult(check="swallowed", crashed=True, notes=[note]),
    ]
    try:
        if _still_current(is_current):
            _upsert_comment(repo, target.number, render_comment(results, ref), app_id, results)
    except Exception:
        log.exception("Could not update the comment after a read failure")


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
