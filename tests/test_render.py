from __future__ import annotations

from agent_permission_diff_bot.checks.model import CheckFinding, CheckResult, DeliberateCatch
from agent_permission_diff_bot.checks.render import (
    COMMENT_MARKER,
    RepoRef,
    conclusion,
    render_check_output,
    render_comment,
)
from agent_permission_diff_bot.model import Severity

REPO = RepoRef(full_name="octo-demo/guard-demo", head_sha="0123456789abcdef" * 2 + "01234567")


def finding(
    title: str = "New allow rule `Bash`", severity: Severity = Severity.HIGH, **extra: object
) -> CheckFinding:
    values: dict[str, object] = {
        "check": "config-guard",
        "rule_id": "CG001",
        "severity": severity,
        "title": title,
        "path": ".claude/settings.json",
        "allows": ("Matches every command",),
        "fix": "Name each command the work needs.",
        "line": 4,
    }
    values.update(extra)
    return CheckFinding(**values)  # type: ignore[arg-type]


def test_comment_has_marker_rank_location_and_fix() -> None:
    body = render_comment([CheckResult("config-guard", [finding()])], REPO)
    assert body.startswith(COMMENT_MARKER)
    assert "1. 🟧 **New allow rule `Bash`**" in body
    assert "/blob/" + REPO.head_sha + "/.claude/settings.json#L4" in body
    assert "Fix: Name each command the work needs." in body


def test_comment_stays_short() -> None:
    findings = [finding(f"Rule {n}") for n in range(8)]
    body = render_comment([CheckResult("config-guard", findings)], REPO)
    assert "5. " in body and "6. " not in body
    assert "…and 3 more in the **Agent Config Guard** check." in body


def test_check_run_output_lists_everything_with_annotations() -> None:
    findings = [finding(f"Rule {n}") for n in range(8)]
    output = render_check_output(CheckResult("config-guard", findings), REPO)
    assert output["title"] == "8 findings (8 high)"
    assert "8. " in output["summary"]
    assert len(output["annotations"]) == 8
    assert output["annotations"][0]["annotation_level"] == "failure"


def test_pr_controlled_text_cannot_hide_the_rest_of_the_comment() -> None:
    hostile = finding(
        "New instruction tells agents to skip a check",
        allows=("Agents are told: “<!-- hide everything --> <img src=x>”",),
    )
    html = _html(render_comment([CheckResult("config-guard", [hostile])], REPO))
    assert html.count("<!--") == 1, "only the bot's own marker may open an HTML comment"
    assert "<img" not in html
    assert "everything" in html, "the rest of the comment stays visible"


def test_code_spans_keep_their_angle_brackets() -> None:
    item = finding(fix="Mark it `swallowed: ok <reason>`.")
    body = render_comment([CheckResult("config-guard", [item])], REPO)
    assert "`swallowed: ok <reason>`" in body


def test_credential_values_are_redacted() -> None:
    leaky = finding(allows=("Runs `deploy --token=synthetic-value-123`",))
    body = render_comment([CheckResult("config-guard", [leaky])], REPO)
    assert "synthetic-value-123" not in body


def test_deliberate_catches_are_listed_but_not_counted() -> None:
    result = CheckResult(
        "swallowed", deliberate=[DeliberateCatch("x.py", 3, "best effort cleanup")]
    )
    body = render_comment([result], REPO)
    assert "Marked deliberate, not ranked" in body and "best effort cleanup" in body
    assert conclusion(result, Severity.LOW) == "success"


def test_conclusions() -> None:
    assert conclusion(CheckResult("config-guard"), Severity.HIGH) == "success"
    medium = CheckResult("config-guard", [finding(severity=Severity.MEDIUM)])
    assert conclusion(medium, Severity.HIGH) == "neutral"
    assert conclusion(CheckResult("config-guard", [finding()]), Severity.HIGH) == "failure"
    assert conclusion(CheckResult("swallowed", [finding()]), None) == "neutral"


def test_hostile_file_names_and_notes_stay_inert() -> None:
    hostile = finding(path="a`<details>`.py")
    result = CheckResult("config-guard", [hostile], notes=["`x`` <img src=x> ```"])
    body = render_comment([result], REPO)
    output = render_check_output(result, REPO)
    assert "<details" not in _html(body)
    assert "<img" not in _html(output["summary"])
    assert "``a`<details>`.py:4``" in body


def test_md_code_survives_backticks() -> None:
    from agent_permission_diff_bot.checks.model import md_code

    assert md_code("a`b") == "``a`b``"
    assert md_code("`x`") == "`` `x` ``"


def _html(markdown: str) -> str:
    from markdown_it import MarkdownIt

    return MarkdownIt("commonmark").render(markdown)


def test_escaped_backtick_cannot_smuggle_html_into_the_rendered_comment() -> None:
    hostile = finding(
        "New instruction tells agents to skip a check",
        allows=("Agents are told: “Skip tests \\`<details><summary>Safe change</summary>`”",),
    )
    html = _html(render_comment([CheckResult("config-guard", [hostile])], REPO))
    assert "<details" not in html and "<summary" not in html


def test_truncated_title_cannot_unbalance_the_location_code_span() -> None:
    rule = "Bash(" + "a" * 200 + ")"
    hostile = finding(
        f"New allow rule `{rule}` while `x` runs",
        path=".claude/skills/<details>/SKILL.md",
    )
    for markdown in (
        render_comment([CheckResult("config-guard", [hostile])], REPO),
        render_check_output(CheckResult("config-guard", [hostile]), REPO)["summary"],
    ):
        assert "<details" not in _html(markdown)


def test_a_crashed_check_never_reads_as_passed() -> None:
    crashed = CheckResult("config-guard", crashed=True, notes=["The check did not finish: X."])
    assert conclusion(crashed, None) == "failure"
    assert conclusion(CheckResult("swallowed", crashed=True), None) == "neutral"
    output = render_check_output(crashed, REPO)
    assert output["title"] == "The check did not finish"
    assert "widens" not in output["summary"]


def test_pr_text_cannot_add_links_emphasis_or_images() -> None:
    hostile = finding(
        allows=("Told: [Approved by security](https://evil.example) **safe** ![x](y)",)
    )
    html = _html(render_comment([CheckResult("config-guard", [hostile])], REPO))
    assert 'evil.example"' not in html and "<strong>safe" not in html and "<img" not in html


def test_redaction_runs_before_escaping_so_spans_stay_closed() -> None:
    hostile = finding(
        title="New `PreToolUse` hook",
        allows=("Runs `true --token=synthetic-value` for tools matching `<details><summary>x`",),
    )
    body = render_comment([CheckResult("config-guard", [hostile])], REPO)
    html = _html(body)
    assert "synthetic-value" not in body
    assert "<details" not in html and "<summary" not in html


def test_quoted_mentions_do_not_ping_anyone() -> None:
    hostile = finding(allows=("Agents are told: “ask @security-team or @octocat to approve”",))
    body = render_comment([CheckResult("config-guard", [hostile])], REPO)
    assert "@security-team" not in body and "@octocat" not in body
    assert "@⁠security-team" in body
