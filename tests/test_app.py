"""The GitHub App, end to end against recorded webhooks and an in-memory GitHub."""

from __future__ import annotations

import json
import time
from pathlib import Path

import httpx
import pytest

from agent_permission_diff_bot.app.fake_github import commit_sha
from agent_permission_diff_bot.app.pipeline import target_from_event
from agent_permission_diff_bot.app.replay import Recording, Replayer
from agent_permission_diff_bot.app.settings import AppSettings, SettingsError
from agent_permission_diff_bot.checks.render import COMMENT_MARKER

FIXTURES = Path(__file__).parent / "fixtures" / "app"


def run(name: str) -> Replayer:
    replayer = Replayer(Recording.load(FIXTURES / name))
    assert replayer.send() == 202
    return replayer


def conclusions(replayer: Replayer) -> dict[str, str]:
    return {run["name"]: run["conclusion"] for run in replayer.github.check_runs.values()}


def bot_comments(replayer: Replayer) -> list[str]:
    return [
        str(c["body"]) for c in replayer.github.comments.values() if c["performed_via_github_app"]
    ]


def test_broad_bash_allow_fails_config_guard_and_comments_what_it_allows() -> None:
    replayer = run("broad-bash-allow")

    assert conclusions(replayer) == {
        "Agent Config Guard": "failure",
        "Swallowed errors": "success",
    }
    [body] = bot_comments(replayer)
    assert body.startswith(COMMENT_MARKER)
    assert "New allow rule `Bash(git *)`" in body
    assert "Inline config makes git run a program you name" in body
    assert "Fix: Replace with `Bash(git status *)`" in body


def test_silent_except_pass_is_reported_as_neutral_swallowed_check() -> None:
    replayer = run("silent-except")

    assert conclusions(replayer) == {
        "Agent Config Guard": "success",
        "Swallowed errors": "neutral",
    }
    [body] = bot_comments(replayer)
    assert "`Exception` dropped around a write" in body
    assert "shop/store.py#L10" in body
    runs = {run["name"]: run for run in replayer.github.check_runs.values()}
    [annotation] = runs["Swallowed errors"]["output"]["annotations"]
    assert (annotation["path"], annotation["start_line"]) == ("shop/store.py", 10)


def test_typescript_catches_are_ranked() -> None:
    [body] = bot_comments(run("ts-swallowed-catch"))
    assert body.index("`.catch()` dropped around a write") < body.index(
        "`catch` dropped around a network call"
    )


def test_hook_mcp_and_instruction_changes_in_one_ranked_comment() -> None:
    replayer = run("hook-mcp-instructions")
    [body] = bot_comments(replayer)
    order = [
        body.index("New `SessionStart` hook"),
        body.index("New MCP server `orders-db`"),
        body.index("New instruction tells agents to skip a check"),
    ]
    assert order == sorted(order)
    assert "ORDERS_DB_TOKEN" in body


def test_deliberate_catch_is_noted_and_does_not_flag_the_check() -> None:
    replayer = run("deliberate-and-clean")
    assert conclusions(replayer)["Swallowed errors"] == "success"
    [body] = bot_comments(replayer)
    assert "already gone is the goal" in body


def test_clean_pull_request_passes_without_a_comment() -> None:
    replayer = run("clean")
    assert set(conclusions(replayer).values()) == {"success"}
    assert bot_comments(replayer) == []


def test_new_push_updates_the_same_comment_in_place() -> None:
    first = Recording.load(FIXTURES / "broad-bash-allow")
    replayer = Replayer(first)
    assert replayer.send() == 202

    fixed = dict(first.head)
    fixed[".claude/settings.json"] = first.head[".claude/settings.json"].replace(
        '"Bash(git *)"', '"Bash(git diff *)"'
    )
    payload = json.loads(json.dumps(first.payload))
    payload["action"] = "synchronize"
    payload["pull_request"]["head"]["sha"] = commit_sha(fixed)
    assert replayer.send(Recording("pull_request", payload, first.base, fixed)) == 202

    [body] = bot_comments(replayer)
    assert "Bash(git *)" not in body
    assert "Bash(git diff *)" in body
    assert (
        sum(
            1
            for request in replayer.github.requests
            if request.startswith("POST /repos/octo-demo/guard-demo/issues/")
        )
        == 1
    )
    assert (
        sum(
            1
            for request in replayer.github.requests
            if request.startswith("PATCH /repos/octo-demo/guard-demo/issues/comments/")
        )
        == 1
    )


def test_a_human_comment_quoting_the_marker_is_never_edited() -> None:
    replayer = Replayer(Recording.load(FIXTURES / "silent-except"))
    human = replayer.github.add_comment(f"{COMMENT_MARKER} copied by hand")
    assert replayer.send() == 202
    assert replayer.github.comments[human]["body"] == f"{COMMENT_MARKER} copied by hand"
    assert len(bot_comments(replayer)) == 1


def test_bad_signature_is_rejected_before_anything_runs() -> None:
    replayer = Replayer(Recording.load(FIXTURES / "broad-bash-allow"))
    assert replayer.send(signature="sha256=" + "0" * 64) == 401
    assert replayer.send(signature="") == 401
    assert replayer.github.requests == []


def test_ping_and_unrelated_events_do_nothing() -> None:
    recording = Recording.load(FIXTURES / "broad-bash-allow")
    replayer = Replayer(recording)
    closed = json.loads(json.dumps(recording.payload))
    closed["action"] = "closed"
    assert replayer.send(Recording("pull_request", closed, recording.base, recording.head)) == 202
    assert replayer.send(Recording("ping", {"zen": "hi"}, {}, {})) == 200
    assert replayer.github.requests == []


def test_rerequested_check_run_reruns_the_pull_request() -> None:
    recording = Recording.load(FIXTURES / "silent-except")
    pull = recording.payload["pull_request"]
    payload = {
        "action": "rerequested",
        "check_run": {
            "name": "Swallowed errors",
            "pull_requests": [
                {"number": pull["number"], "base": pull["base"], "head": pull["head"]}
            ],
        },
        "repository": recording.payload["repository"],
        "installation": recording.payload["installation"],
    }
    replayer = Replayer(recording)
    assert replayer.send(Recording("check_run", payload, recording.base, recording.head)) == 202
    assert conclusions(replayer)["Swallowed errors"] == "neutral"


def test_read_failure_fails_config_guard_closed() -> None:
    replayer = Replayer(Recording.load(FIXTURES / "broad-bash-allow"))
    replayer.github._tree = lambda body, sha: httpx.Response(500)  # type: ignore[method-assign]
    assert replayer.send() == 202
    assert conclusions(replayer) == {
        "Agent Config Guard": "failure",
        "Swallowed errors": "neutral",
    }
    [body] = bot_comments(replayer)
    assert "did not finish" in body
    assert "No new agent permission widening" not in body


def test_target_ignores_closed_and_foreign_check_runs() -> None:
    payload = json.loads((FIXTURES / "clean" / "event.json").read_text())["payload"]
    assert target_from_event("pull_request", payload) is not None
    payload["pull_request"]["state"] = "closed"
    assert target_from_event("pull_request", payload) is None
    foreign = {
        "action": "rerequested",
        "check_run": {"name": "CI", "pull_requests": [{"number": 1}]},
        "repository": payload["repository"],
        "installation": payload["installation"],
    }
    assert target_from_event("check_run", foreign) is None


def test_settings_errors_name_the_setting_not_the_value(tmp_path: Path) -> None:
    key = tmp_path / "app.pem"
    key.write_text("-----BEGIN PRIVATE KEY-----\nsynthetic\n-----END PRIVATE KEY-----\n")
    env = {
        "APDB_APP_ID": "12345",
        "APDB_PRIVATE_KEY_PATH": str(key),
        "APDB_WEBHOOK_SECRET": "synthetic-webhook-secret",
    }
    settings = AppSettings.from_env(env)
    assert "synthetic" not in repr(settings)
    with pytest.raises(SettingsError, match="APDB_WEBHOOK_SECRET") as error:
        AppSettings.from_env({**env, "APDB_WEBHOOK_SECRET": "short"})
    assert "short" not in str(error.value)
    with pytest.raises(SettingsError, match=r"fail-on settings"):
        AppSettings.from_env({**env, "APDB_GUARD_FAIL_ON": "sometimes"})
    assert AppSettings.from_env({**env, "APDB_GUARD_FAIL_ON": "never"}).guard_fail_on is None


def test_stale_branch_is_compared_with_its_merge_base_not_the_base_tip() -> None:
    recording = Recording.load(FIXTURES / "clean")
    branch_point = dict(recording.base)
    branch_point[".claude/settings.json"] = recording.base[".claude/settings.json"].replace(
        '"Bash(npm test)"', '"Bash(npm test)",\n      "Bash(git *)"'
    )
    head = dict(branch_point)
    head["README.md"] = recording.head["README.md"]
    payload = json.loads(json.dumps(recording.payload))
    payload["pull_request"]["head"]["sha"] = commit_sha(head)
    replayer = Replayer(Recording("pull_request", payload, recording.base, head))
    replayer.github.merge_base_sha = commit_sha(branch_point)
    replayer.github.commits[replayer.github.merge_base_sha] = branch_point
    assert replayer.send() == 202
    assert conclusions(replayer)["Agent Config Guard"] == "success"


def test_padding_a_pr_with_agent_files_cannot_hide_a_settings_change() -> None:
    recording = Recording.load(FIXTURES / "broad-bash-allow")
    head = dict(recording.head)
    for n in range(300):
        head[f".claude/agents/a{n:03}.md"] = f"---\nname: a{n}\n---\nHelper {n}.\n"
    payload = json.loads(json.dumps(recording.payload))
    payload["pull_request"]["head"]["sha"] = commit_sha(head)
    replayer = Replayer(Recording("pull_request", payload, recording.base, head))
    assert replayer.send() == 202
    assert conclusions(replayer)["Agent Config Guard"] == "failure"
    [body] = bot_comments(replayer)
    assert "Bash(git *)" in body


def test_a_crashed_check_never_reads_as_all_clear(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*args: object) -> object:
        raise RuntimeError("synthetic crash")

    monkeypatch.setattr("agent_permission_diff_bot.app.pipeline.run_config_guard", boom)
    replayer = run("clean")
    assert conclusions(replayer)["Agent Config Guard"] == "failure"
    [body] = bot_comments(replayer)
    assert "did not finish" in body
    assert "No new agent permission widening" not in body


def test_an_older_push_finishing_late_does_not_overwrite_the_comment() -> None:
    from agent_permission_diff_bot.app.github import RepoClient, make_http
    from agent_permission_diff_bot.app.pipeline import run_checks

    replayer = Replayer(Recording.load(FIXTURES / "broad-bash-allow"))
    payload = replayer.recording.payload
    target = target_from_event("pull_request", payload)
    assert target is not None
    replayer.github.set_pull(replayer.recording.base, replayer.recording.head)
    http = make_http("https://api.github.test", replayer.github.transport())
    repo = RepoClient(
        http=http, owner="octo-demo", name="guard-demo", token="ghs_replay_installation_token"
    )
    answers = iter(["current", "new-head", "new-head"])
    outcome = run_checks(
        repo,
        target,
        app_id="123456",
        guard_fail_on=None,
        swallowed_fail_on=None,
        freshness=lambda: next(answers),  # type: ignore[arg-type, return-value]
    )
    assert outcome.comment_action == "stale"
    assert bot_comments(replayer) == []
    runs = list(replayer.github.check_runs.values())
    assert len(runs) == 2 and all(run_["conclusion"] == "cancelled" for run_ in runs)


def test_rerun_from_a_fork_finds_the_pull_request_by_head_commit() -> None:
    recording = Recording.load(FIXTURES / "silent-except")
    head_sha = recording.payload["pull_request"]["head"]["sha"]
    payload = {
        "action": "rerequested",
        "check_suite": {"head_sha": head_sha, "pull_requests": []},
        "repository": recording.payload["repository"],
        "installation": recording.payload["installation"],
    }
    replayer = Replayer(recording)
    replayer.github.set_pull(recording.base, recording.head)
    assert replayer.send(Recording("check_suite", payload, {}, {})) == 202
    assert conclusions(replayer)["Swallowed errors"] == "neutral"


def test_oversized_body_is_refused_before_it_is_read() -> None:
    replayer = Replayer(Recording.load(FIXTURES / "clean"))
    response = replayer.client.post(
        "/webhook", content=b"{}", headers={"Content-Length": str(26 * 1024 * 1024)}
    )
    assert response.status_code == 413


def test_cli_app_command_runs_as_a_module() -> None:
    import subprocess
    import sys

    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "agent_permission_diff_bot.cli",
            "app",
            "replay",
            str(FIXTURES / "clean"),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    assert "comment: none" in completed.stdout


def test_a_late_webhook_for_an_older_push_cannot_overwrite_the_comment() -> None:
    first = Recording.load(FIXTURES / "broad-bash-allow")
    newer_head = dict(first.head)
    newer_head[".claude/settings.json"] = first.head[".claude/settings.json"].replace(
        '"Bash(git *)"', '"Bash(git diff *)"'
    )
    newer = json.loads(json.dumps(first.payload))
    newer["action"] = "synchronize"
    newer["pull_request"]["head"]["sha"] = commit_sha(newer_head)
    replayer = Replayer(first)
    assert replayer.send(Recording("pull_request", newer, first.base, newer_head)) == 202
    assert replayer.send(first, advance_head=False) == 202
    [body] = bot_comments(replayer)
    assert "Bash(git diff *)" in body and "Bash(git *)" not in body


def test_truncated_tree_fails_config_guard_closed() -> None:
    from agent_permission_diff_bot.app.snapshot import collect_inputs
    from agent_permission_diff_bot.checks.config_guard import run_config_guard

    class Truncated:
        def tree(self, sha: str) -> tuple[dict[str, dict[str, object]], bool]:
            return {"README.md": {"sha": "1", "mode": "100644", "size": 3}}, True

        def blob_text(self, sha: str, max_bytes: int) -> str:
            return "hi\n"

    files = [
        {"filename": "README.md", "status": "modified", "sha": "1", "patch": "@@ -1 +1 @@\n+hi"}
    ]
    inputs = collect_inputs(Truncated(), "b" * 40, "h" * 40, files)
    found = run_config_guard(inputs.base_files, inputs.head_files).findings
    assert any(f.rule_id == "APD013" and f.severity >= 3 for f in found)


def test_large_source_files_are_skipped_before_download() -> None:
    from agent_permission_diff_bot.app.snapshot import collect_inputs

    class Big:
        def __init__(self) -> None:
            self.downloads: list[str] = []

        def tree(self, sha: str) -> tuple[dict[str, dict[str, object]], bool]:
            return {"big.py": {"sha": "f" * 40, "mode": "100644", "size": 50 * 1024 * 1024}}, False

        def blob_text(self, sha: str, max_bytes: int) -> str:
            self.downloads.append(sha)
            return ""

    repo = Big()
    files = [
        {"filename": "big.py", "status": "modified", "sha": "f" * 40, "patch": "@@ -1 +1 @@\n+x"}
    ]
    inputs = collect_inputs(repo, "b" * 40, "h" * 40, files)
    assert inputs.swallowed_files == []
    assert repo.downloads == []
    assert any("over 1 MiB" in note for note in inputs.swallowed_notes)


def test_a_late_delivery_checks_the_files_of_its_own_commit() -> None:
    first = Recording.load(FIXTURES / "clean")
    risky = dict(first.base)
    risky["AGENTS.md"] = first.base["AGENTS.md"] + "Skip the tests when CI is slow.\n"
    older = json.loads(json.dumps(first.payload))
    older["pull_request"]["head"]["sha"] = commit_sha(risky)
    newer_payload = json.loads(json.dumps(first.payload))
    newer_payload["action"] = "synchronize"
    replayer = Replayer(Recording("pull_request", newer_payload, first.base, first.head))
    assert replayer.send() == 202
    assert (
        replayer.send(Recording("pull_request", older, first.base, risky), advance_head=False)
        == 202
    )
    old_runs = [
        run for run in replayer.github.check_runs.values() if run["head_sha"] == commit_sha(risky)
    ]
    assert old_runs == [], "a late delivery for a superseded head publishes nothing"
    assert bot_comments(replayer) == [], "the newer, clean head owns the comment"


def test_a_read_failure_replaces_an_older_all_clear_or_findings_comment() -> None:
    first = Recording.load(FIXTURES / "broad-bash-allow")
    replayer = Replayer(first)
    assert replayer.send() == 202
    second_head = dict(first.head)
    second_head["README.md"] = first.head["README.md"] + "More.\n"
    payload = json.loads(json.dumps(first.payload))
    payload["action"] = "synchronize"
    payload["pull_request"]["head"]["sha"] = commit_sha(second_head)
    replayer.github._tree = lambda body, sha: httpx.Response(500)  # type: ignore[method-assign]
    assert replayer.send(Recording("pull_request", payload, first.base, second_head)) == 202
    [body] = bot_comments(replayer)
    assert "did not finish" in body
    assert "Bash(git *)" not in body


def test_a_failed_second_check_run_does_not_strand_the_first() -> None:
    replayer = Replayer(Recording.load(FIXTURES / "clean"))
    original = replayer.github._create_run
    calls = {"n": 0}

    def flaky(body: object) -> httpx.Response:
        calls["n"] += 1
        return original(body) if calls["n"] == 1 else httpx.Response(500)

    replayer.github._create_run = flaky  # type: ignore[method-assign]
    assert replayer.send() == 202
    [run_] = replayer.github.check_runs.values()
    assert run_["status"] == "completed" and run_["conclusion"] == "failure"


def test_blob_reads_stop_at_the_cap_with_or_without_a_length() -> None:
    from agent_permission_diff_bot.app.github import BlobTooLargeError, RepoClient, make_http

    def big(request: httpx.Request) -> httpx.Response:
        body = b"x" * 4096
        if request.url.path.endswith("/chunked"):
            return httpx.Response(200, content=iter([body[:2048], body[2048:]]))
        return httpx.Response(200, content=body)

    http = make_http("https://api.github.test", httpx.MockTransport(big))
    repo = RepoClient(http=http, owner="o", name="r", token="t")
    for sha in ("sized", "chunked"):
        with pytest.raises(BlobTooLargeError):
            repo.blob_text(sha, 1000)
    assert repo.blob_text("sized", 10_000) == "x" * 4096


def test_a_source_file_missing_from_a_truncated_tree_is_read_with_a_cap() -> None:
    from agent_permission_diff_bot.app.github import BlobTooLargeError
    from agent_permission_diff_bot.app.snapshot import collect_inputs

    class Truncated:
        def __init__(self) -> None:
            self.caps: list[int] = []

        def tree(self, sha: str) -> tuple[dict[str, dict[str, object]], bool]:
            return {}, True

        def blob_text(self, sha: str, max_bytes: int) -> str:
            self.caps.append(max_bytes)
            raise BlobTooLargeError(sha)

    repo = Truncated()
    files = [
        {"filename": "big.py", "status": "modified", "sha": "f" * 40, "patch": "@@ -1 +1 @@\n+x"}
    ]
    inputs = collect_inputs(repo, "b" * 40, "h" * 40, files)
    assert inputs.swallowed_files == []
    assert repo.caps and all(cap <= 1024 * 1024 for cap in repo.caps)


def test_runs_for_one_pull_request_queue_instead_of_parking_threads() -> None:
    import threading

    from agent_permission_diff_bot.app.server import PullRuns

    runs = PullRuns()
    order: list[str] = []
    started, release = threading.Event(), threading.Event()

    def first() -> None:
        started.set()
        release.wait(5)
        order.append("first")

    worker = threading.Thread(target=lambda: runs.submit((1, 1), ("a", "main"), first))
    worker.start()
    assert started.wait(5)
    began = time.monotonic()
    assert runs.submit((1, 1), ("b", "main"), lambda: order.append("second")) is False
    assert runs.submit((1, 1), ("b", "main"), lambda: order.append("second again")) is False
    assert time.monotonic() - began < 1, "a busy pull request never blocks the caller"
    assert runs.submit((1, 2), ("c", "main"), lambda: order.append("other PR")) is True
    release.set()
    worker.join(5)
    assert order == ["other PR", "first", "second again"]
    assert runs.busy() == 0, "nothing is kept once a pull request's queue is empty"


def test_serve_without_settings_exits_cleanly(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from agent_permission_diff_bot.cli import main

    for name in ("APDB_APP_ID", "APDB_PRIVATE_KEY_PATH", "APDB_WEBHOOK_SECRET"):
        monkeypatch.delenv(name, raising=False)
    assert main(["app", "serve"]) == 2
    assert "APDB_APP_ID" in capsys.readouterr().err


def _edited(recording: Recording, *, base_changed: bool) -> Recording:
    payload = json.loads(json.dumps(recording.payload))
    payload["action"] = "edited"
    payload["changes"] = (
        {"base": {"ref": {"from": "dev"}}} if base_changed else {"title": {"from": "x"}}
    )
    return Recording("pull_request", payload, recording.base, recording.head)


def test_retargeting_the_base_branch_runs_the_checks_again() -> None:
    recording = Recording.load(FIXTURES / "broad-bash-allow")
    replayer = Replayer(recording)
    assert replayer.send(_edited(recording, base_changed=True)) == 202
    assert conclusions(replayer)["Agent Config Guard"] == "failure"


def test_editing_only_the_title_does_not_run_the_checks() -> None:
    recording = Recording.load(FIXTURES / "broad-bash-allow")
    replayer = Replayer(recording)
    assert replayer.send(_edited(recording, base_changed=False)) == 202
    assert replayer.github.check_runs == {}


def test_hook_script_reads_count_against_the_file_limit() -> None:
    from agent_permission_diff_bot.app.snapshot import MAX_GUARD_FILES, collect_inputs
    from agent_permission_diff_bot.checks.config_guard import run_config_guard

    hooks = [
        {"hooks": [{"type": "command", "command": f"bash scripts/s{n}.sh"}]} for n in range(500)
    ]
    settings = json.dumps({"hooks": {"SessionStart": hooks}})
    tree = {".claude/settings.json": {"sha": "cfg", "mode": "100644", "size": len(settings)}}
    tree.update(
        {f"scripts/s{n}.sh": {"sha": f"s{n}", "mode": "100644", "size": 10} for n in range(500)}
    )

    class Repo:
        def __init__(self) -> None:
            self.reads = 0

        def tree(self, sha: str) -> tuple[dict[str, dict[str, object]], bool]:
            return tree, False

        def blob_text(self, sha: str, max_bytes: int) -> str:
            self.reads += 1
            return settings if sha == "cfg" else "#!/bin/sh\ntrue\n"

    repo = Repo()
    changed = [
        {
            "filename": ".claude/settings.json",
            "status": "modified",
            "sha": "cfg",
            "patch": "@@ -1 +1 @@\n+x",
        }
    ]
    inputs = collect_inputs(repo, "b" * 40, "h" * 40, changed)
    assert repo.reads <= 2 * MAX_GUARD_FILES, "base and head snapshots each stay within the limit"
    found = run_config_guard(inputs.base_files, inputs.head_files).findings
    assert any(f.rule_id == "APD013" for f in found), "unread scripts are reported, not ignored"


def test_a_failed_completion_never_strands_a_check_run_in_progress() -> None:
    replayer = Replayer(Recording.load(FIXTURES / "broad-bash-allow"))
    original = replayer.github._update_run
    failed: list[str] = []

    def flaky(body: object, id: str) -> httpx.Response:
        if not failed:
            failed.append(id)
            return httpx.Response(502)
        return original(body, id)

    replayer.github._update_run = flaky  # type: ignore[method-assign]
    assert replayer.send() == 202
    assert all(run_["status"] == "completed" for run_ in replayer.github.check_runs.values())


def test_no_comment_is_written_when_freshness_cannot_be_confirmed() -> None:
    replayer = Replayer(Recording.load(FIXTURES / "broad-bash-allow"))
    replayer.github._pull = lambda body: httpx.Response(502)  # type: ignore[method-assign]
    assert replayer.send() == 202
    assert bot_comments(replayer) == []
    assert conclusions(replayer)["Agent Config Guard"] == "failure", "check runs still land"


def test_a_rerun_checks_the_commit_that_was_clicked() -> None:
    recording = Recording.load(FIXTURES / "silent-except")
    pull = recording.payload["pull_request"]
    clicked = commit_sha(recording.base)
    payload = {
        "action": "rerequested",
        "check_run": {
            "name": "Swallowed errors",
            "head_sha": clicked,
            "pull_requests": [
                {"number": pull["number"], "base": pull["base"], "head": pull["head"]}
            ],
        },
        "repository": recording.payload["repository"],
        "installation": recording.payload["installation"],
    }
    replayer = Replayer(recording)
    replayer.github.set_pull(recording.base, recording.head)
    replayer.github.commits[clicked] = recording.base
    replayer.send(
        Recording("check_run", payload, recording.base, recording.head), advance_head=False
    )
    assert {run_["head_sha"] for run_ in replayer.github.check_runs.values()} == {clicked}


def test_a_fork_rerun_falls_back_to_the_open_pull_requests() -> None:
    recording = Recording.load(FIXTURES / "silent-except")
    head_sha = recording.payload["pull_request"]["head"]["sha"]
    payload = {
        "action": "rerequested",
        "check_suite": {"head_sha": head_sha, "pull_requests": []},
        "repository": recording.payload["repository"],
        "installation": recording.payload["installation"],
    }
    replayer = Replayer(recording)
    replayer.github.set_pull(recording.base, recording.head)
    replayer.github.fork_lookup_empty = True
    assert replayer.send(Recording("check_suite", payload, {}, {})) == 202
    assert conclusions(replayer)["Swallowed errors"] == "neutral"


def _signed_post(replayer: Replayer, event: str, body: bytes) -> int:
    import hashlib
    import hmac

    digest = hmac.new(replayer.secret.encode(), body, hashlib.sha256).hexdigest()
    response = replayer.client.post(
        "/webhook",
        content=body,
        headers={"X-GitHub-Event": event, "X-Hub-Signature-256": f"sha256={digest}"},
    )
    return response.status_code


def test_signed_but_malformed_payloads_get_a_clear_400() -> None:
    recording = Recording.load(FIXTURES / "clean")
    replayer = Replayer(recording)
    assert _signed_post(replayer, "pull_request", b"\xff\xfe not utf-8") == 400
    assert _signed_post(replayer, "pull_request", b"[1, 2]") == 400
    broken = json.loads(json.dumps(recording.payload))
    del broken["pull_request"]["head"]
    assert _signed_post(replayer, "pull_request", json.dumps(broken).encode()) == 400
    assert replayer.github.check_runs == {}


def test_a_delayed_run_for_the_old_base_publishes_nothing_after_a_retarget() -> None:
    recording = Recording.load(FIXTURES / "broad-bash-allow")
    replayer = Replayer(recording)
    replayer.github.base_ref = "release"  # the PR now targets another branch
    stale = json.loads(json.dumps(recording.payload))
    stale["pull_request"]["base"]["ref"] = "main"
    assert replayer.send(Recording("pull_request", stale, recording.base, recording.head)) == 202
    assert replayer.github.check_runs == {}
    assert bot_comments(replayer) == []


def test_a_rerun_ignores_pull_requests_into_other_repositories() -> None:
    recording = Recording.load(FIXTURES / "silent-except")
    pull = recording.payload["pull_request"]
    foreign = {
        "number": 77,
        "base": {"sha": "0" * 40, "ref": "main", "repo": {"id": 1}},
        "head": pull["head"],
    }
    payload = {
        "action": "rerequested",
        "check_run": {
            "name": "Swallowed errors",
            "head_sha": pull["head"]["sha"],
            "pull_requests": [foreign],
        },
        "repository": recording.payload["repository"],
        "installation": recording.payload["installation"],
    }
    target = target_from_event("check_run", payload)
    assert target is not None and target.number == 0, "looked up in this repository instead"


def test_a_non_ascii_signature_is_a_401_not_a_crash() -> None:
    replayer = Replayer(Recording.load(FIXTURES / "clean"))
    response = replayer.client.post(
        "/webhook",
        content=b"{}",
        headers=[
            (b"X-GitHub-Event", b"ping"),
            (b"X-Hub-Signature-256", "sha256=\u00e9".encode("latin-1")),
        ],
    )
    assert response.status_code == 401


def test_a_pure_rename_is_not_called_too_large() -> None:
    from agent_permission_diff_bot.app.snapshot import collect_inputs

    class Repo:
        def tree(self, sha: str) -> tuple[dict[str, dict[str, object]], bool]:
            return {}, False

        def blob_text(self, sha: str, max_bytes: int) -> str:
            raise AssertionError("nothing to download for a pure rename")

    files = [
        {
            "filename": "b.py",
            "previous_filename": "a.py",
            "status": "renamed",
            "changes": 0,
            "sha": "s",
        }
    ]
    inputs = collect_inputs(Repo(), "b" * 40, "h" * 40, files)
    assert not any("too large" in note for note in inputs.swallowed_notes)


def test_a_malformed_payload_answer_does_not_echo_details() -> None:
    recording = Recording.load(FIXTURES / "clean")
    replayer = Replayer(recording)
    broken = json.loads(json.dumps(recording.payload))
    del broken["pull_request"]["head"]
    body = json.dumps(broken).encode()
    import hashlib
    import hmac

    digest = hmac.new(replayer.secret.encode(), body, hashlib.sha256).hexdigest()
    response = replayer.client.post(
        "/webhook",
        content=body,
        headers={"X-GitHub-Event": "pull_request", "X-Hub-Signature-256": f"sha256={digest}"},
    )
    assert response.status_code == 400
    assert response.json() == {"error": "payload is missing required fields"}
