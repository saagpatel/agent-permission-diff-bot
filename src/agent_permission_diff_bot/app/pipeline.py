"""Handle one pull request event: two check runs and one comment, updated in place."""

from __future__ import annotations

import logging
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, replace
from typing import Any, Literal

from agent_permission_diff_bot.app.analysis import AnalysisLimits, run_analysis
from agent_permission_diff_bot.app.github import RepoClient
from agent_permission_diff_bot.app.snapshot import collect_inputs
from agent_permission_diff_bot.checks.model import CheckName, CheckResult
from agent_permission_diff_bot.checks.render import (
    CHECK_NAMES,
    COMMENT_MARKER,
    RepoRef,
    conclusion,
    render_check_output,
    render_comment,
)
from agent_permission_diff_bot.model import Severity

log = logging.getLogger(__name__)

# "new-head": the PR points at another commit; "new-base": it targets another branch.
Freshness = Literal["current", "new-head", "new-base", "unknown"]

DEFAULT_LIMITS = AnalysisLimits()

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
    base_ref: str = ""  # the base branch this run is for; a retarget makes the run stale
    rerun: bool = False  # a re-run asked for this exact commit, even if it is not the head


@dataclass
class RunOutcome:
    conclusions: dict[str, str] = field(default_factory=dict)
    # "created", "updated", "unchanged", "stale", "unconfirmed" or "none"
    comment_action: str = "none"
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
        # The list can include pull requests into other repositories (a fork's own PRs);
        # only one whose base is this repository is ours.
        pull = next(
            (
                entry
                for entry in (pulls if isinstance(pulls, list) else [])
                if isinstance(entry, Mapping) and _base_repo_id(entry) == repository.get("id")
            ),
            None,
        )
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
            base_ref=str(pull["base"].get("ref", "")) if pull else "",
            rerun=event != "pull_request",
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise PayloadError(f"pull request fields are missing or malformed: {exc}") from exc


def _base_repo_id(pull: Mapping[str, Any]) -> Any:
    base = pull.get("base")
    repo = base.get("repo") if isinstance(base, Mapping) else None
    return repo.get("id") if isinstance(repo, Mapping) else None


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
                    target,
                    number=int(pull["number"]),
                    base_sha=str(pull["base"]["sha"]),
                    base_ref=str(pull["base"].get("ref", "")),
                )
    return None


def run_checks(
    repo: RepoClient,
    target: PullTarget,
    *,
    app_id: str,
    guard_fail_on: Severity | None,
    swallowed_fail_on: Severity | None,
    freshness: Callable[[], Freshness] | None = None,
    limits: AnalysisLimits = DEFAULT_LIMITS,
) -> RunOutcome:
    """Run both checks for ``target`` and publish them, unless a newer run owns the PR.

    ``freshness`` compares the PR's live head commit and base branch with the run's; by
    default it asks GitHub. A stale run publishes nothing that could replace a newer
    result, and when freshness cannot be confirmed the comment is left alone.
    """
    outcome = RunOutcome()
    ref = RepoRef(full_name=repo.full_name, head_sha=target.head_sha)
    fresh = freshness or (lambda: live_freshness(repo, target))
    if _superseded(fresh(), target):
        outcome.comment_action = "stale"
        return outcome
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
        # Both checks run in a time- and memory-limited child; a pathological PR can only
        # exhaust that child, and then both checks report that they did not finish.
        results = run_analysis(inputs, limits)
    except Exception as exc:
        log.exception("Reading pull request %s#%s failed", repo.full_name, target.number)
        _fail_runs(repo, run_ids, exc)
        _report_unfinished(repo, target, ref, app_id, fresh, exc)
        raise
    if _superseded(fresh(), target):
        # The head or base moved while this ran; the newer run's check runs supersede these.
        _cancel_runs(repo, run_ids)
        outcome.comment_action = "stale"
        return outcome
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
    state = fresh()
    if state != "current":
        # A newer run owns the comment, or GitHub could not confirm this run is current:
        # never risk replacing newer findings with these.
        outcome.comment_action = "unconfirmed" if state == "unknown" else "stale"
        return outcome
    outcome.comment_action = _upsert_comment(repo, target.number, body, app_id, results)
    return outcome


def live_freshness(repo: RepoClient, target: PullTarget) -> Freshness:
    """``current`` when the PR's live head and base branch are the run's.

    ``unknown`` when GitHub cannot say, in which case nothing that could replace a newer
    result (the comment) is written.
    """
    try:
        head_sha, base_ref = repo.pull_state(target.number)
    except Exception:
        log.exception("Could not read the pull request's head and base")
        return "unknown"
    if target.base_ref and base_ref != target.base_ref:
        return "new-base"
    if head_sha != target.head_sha:
        return "new-head"
    return "current"


def _superseded(state: Freshness, target: PullTarget) -> bool:
    """Whether this run's check runs would stand in for a newer result.

    A retargeted pull request always supersedes the run. A newer head supersedes it too,
    except for a re-run someone asked for on this exact commit: its check runs apply to
    that commit only (it never writes the comment unless it is the current head).
    """
    return state == "new-base" or (state == "new-head" and not target.rerun)


def _cancel_runs(repo: RepoClient, run_ids: Mapping[CheckName, int]) -> None:
    output = {
        "title": "Superseded",
        "summary": (
            "The pull request's head or base branch changed while this ran; the newer "
            "run's result is the one that counts."
        ),
    }
    for run_id in run_ids.values():
        try:
            repo.complete_check_run(run_id, "cancelled", output)
        except Exception:
            log.exception("Could not mark check run %s as superseded", run_id)


def _report_unfinished(
    repo: RepoClient,
    target: PullTarget,
    ref: RepoRef,
    app_id: str,
    fresh: Callable[[], Freshness],
    exc: Exception,
) -> None:
    """After a read failure, the comment must not keep showing an older all-clear."""
    note = f"The check did not finish: {type(exc).__name__}. Re-run the check to retry."
    results = [
        CheckResult(check="config-guard", crashed=True, notes=[note]),
        CheckResult(check="swallowed", crashed=True, notes=[note]),
    ]
    try:
        if fresh() == "current":
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
