"""The GitHub App, end to end against recorded webhooks and an in-memory GitHub."""

from __future__ import annotations

import json
from pathlib import Path

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
    replayer.github._tree = lambda body, sha: __import__("httpx").Response(500)  # type: ignore[method-assign]
    assert replayer.send() == 202
    assert conclusions(replayer) == {
        "Agent Config Guard": "failure",
        "Swallowed errors": "neutral",
    }
    assert bot_comments(replayer) == []


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
