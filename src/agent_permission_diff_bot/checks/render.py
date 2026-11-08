"""Render check results as one short pull request comment and as check-run output."""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any, Literal
from urllib.parse import quote

from agent_permission_diff_bot.checks.model import CheckFinding, CheckResult, md_code
from agent_permission_diff_bot.model import Severity
from agent_permission_diff_bot.redaction import redact_text

COMMENT_MARKER = "<!-- agent-permission-diff-bot:pr-comment -->"
COMMENT_LIMIT = 5
ANNOTATION_LIMIT = 50
OUTPUT_LIMIT = 60_000

Conclusion = Literal["success", "neutral", "failure"]

CHECK_NAMES = {"config-guard": "Agent Config Guard", "swallowed": "Swallowed errors"}
_ICON = {
    Severity.CRITICAL: "🟥",
    Severity.HIGH: "🟧",
    Severity.MEDIUM: "🟨",
    Severity.LOW: "🟦",
}
_MARK_HINT = (
    "Mark a deliberate one with a `swallowed: ok <reason>` comment on the except/catch line."
)


@dataclass(frozen=True)
class RepoRef:
    """Where findings link to: ``owner/name`` at the head commit."""

    full_name: str
    head_sha: str

    def link(self, path: str, line: int | None) -> str:
        anchor = f"#L{line}" if line else ""
        return f"https://github.com/{self.full_name}/blob/{self.head_sha}/{quote(path)}{anchor}"


def conclusion(result: CheckResult, fail_on: Severity | None) -> Conclusion:
    """``failure`` at or above ``fail_on``; ``neutral`` for other findings; else ``success``.

    A check that did not finish never passes: Config Guard fails, Swallowed is neutral.
    """
    if result.crashed:
        return "failure" if result.check == "config-guard" else "neutral"
    worst = result.max_severity
    if worst is None:
        return "success"
    if fail_on is not None and worst >= fail_on:
        return "failure"
    return "neutral"


def render_comment(results: list[CheckResult], repo: RepoRef) -> str:
    """One comment for the whole PR, ranked per check, with a suggested fix for each finding."""
    lines = [COMMENT_MARKER]
    for result in results:
        name = CHECK_NAMES[result.check]
        if result.crashed:
            lines.append(f"⚠️ **{name} did not finish**; see the check run. Re-run it to retry.")
        elif result.notes:
            lines.append(
                f"⚠️ {name} read the pull request only partly ({len(result.notes)} coverage "
                "note(s)); see the check run."
            )
    complete = not any(r.crashed or r.notes for r in results)
    if complete and not any(r.findings or r.deliberate for r in results):
        lines.append("No new agent permission widening or swallowed errors in this pull request.")
    for result in results:
        if not result.findings and not result.deliberate:
            continue
        lines.append(f"### {CHECK_NAMES[result.check]}: {_count(result)}")
        for index, finding in enumerate(result.findings[:COMMENT_LIMIT], start=1):
            lines.extend(_comment_item(index, finding, repo))
        hidden = len(result.findings) - COMMENT_LIMIT
        if hidden > 0:
            lines.append(f"\n…and {hidden} more in the **{CHECK_NAMES[result.check]}** check.")
        if result.deliberate:
            marked = "; ".join(
                f"[{md_code(f'{d.path}:{d.line}')}]({repo.link(d.path, d.line)}): "
                f"{_clean(d.reason, 80)}"
                for d in result.deliberate[:COMMENT_LIMIT]
            )
            lines.append(f"\nMarked deliberate, not ranked: {marked}")
        if result.check == "swallowed":
            lines.append(f"\n<sub>{_MARK_HINT}</sub>")
        lines.append("")
    lines.append(
        f"<sub>Static read of the diff at `{repo.head_sha[:7]}`; nothing in the PR was run. "
        "Updated in place on every push.</sub>"
    )
    return "\n".join(lines)


def render_check_output(result: CheckResult, repo: RepoRef) -> dict[str, Any]:
    """The ``output`` object of a completed check run."""
    if result.crashed:
        notes = "\n".join(f"- {_clean(note, 400)}" for note in result.notes)
        return {
            "title": "The check did not finish",
            "summary": (
                "The analysis did not complete, so this pull request was not checked. "
                "Re-run the check to retry.\n\n" + notes
            ),
        }
    title = _count(result) if result.findings else "No findings"
    summary_lines: list[str] = []
    for index, finding in enumerate(result.findings, start=1):
        summary_lines.extend(_comment_item(index, finding, repo, max_allows=5))
    if result.deliberate:
        summary_lines.append("\n**Marked deliberate (not ranked)**\n")
        summary_lines.extend(
            f"- [{md_code(f'{d.path}:{d.line}')}]({repo.link(d.path, d.line)}): "
            f"{_clean(d.reason, 200)}"
            for d in result.deliberate
        )
    if result.notes:
        summary_lines.append("\n**Coverage notes**\n")
        summary_lines.extend(f"- {_clean(note, 400)}" for note in result.notes)
    if result.check == "swallowed":
        summary_lines.append(f"\n{_MARK_HINT}")
    if not summary_lines:
        summary_lines.append(
            "Nothing in this pull request widens agent permissions."
            if result.check == "config-guard"
            else "No new place in this pull request catches an error and drops it."
        )
    summary = "\n".join(summary_lines)
    if len(summary) > OUTPUT_LIMIT:
        summary = summary[: OUTPUT_LIMIT - 40] + "\n\n…truncated; see the PR comment."
    output: dict[str, Any] = {"title": title, "summary": summary}
    annotations = [_annotation(f) for f in result.findings if f.line][:ANNOTATION_LIMIT]
    if annotations:
        output["annotations"] = annotations
    return output


def _comment_item(
    index: int, finding: CheckFinding, repo: RepoRef, max_allows: int = 2
) -> list[str]:
    where = f"{finding.path}:{finding.line}" if finding.line else finding.path
    location = (
        f"[{md_code(where)}]({repo.link(finding.path, finding.line)})" if finding.path else ""
    )
    allows = _join_items(_clean(item, 220) for item in finding.allows[:max_allows])
    label = "Now allows" if finding.check == "config-guard" else "Risk"
    return [
        f"{index}. {_ICON[finding.severity]} **{_clean(finding.title, 140)}** {location}",
        f"   - {label}: {allows}",
        f"   - Fix: {_clean(finding.fix, 400)}",
    ]


def _join_items(items: Iterable[str]) -> str:
    """Join with `; `, or a space after an item that already ends a sentence."""
    joined = ""
    for item in items:
        if joined:
            joined += " " if joined.endswith((".", "!", "?")) else "; "
        joined += item
    return joined


def _annotation(finding: CheckFinding) -> dict[str, Any]:
    level = (
        "failure"
        if finding.check == "config-guard" and finding.severity >= Severity.HIGH
        else "warning"
        if finding.severity >= Severity.MEDIUM
        else "notice"
    )
    message = " ".join(finding.allows) + f"\nFix: {finding.fix}"
    return {
        "path": finding.path,
        "start_line": finding.line,
        "end_line": finding.line,
        "annotation_level": level,
        "title": redact_text(" ".join(finding.title.split()))[:250],
        "message": redact_text(message)[:4000],
    }


def _count(result: CheckResult) -> str:
    total = len(result.findings)
    if not total:
        return f"{len(result.deliberate)} marked deliberate"
    noun = "finding" if result.check == "config-guard" else "new swallowed error"
    plural = noun + ("s" if total != 1 else "")
    by_level = [
        f"{sum(1 for f in result.findings if f.severity == level)} {level.label()}"
        for level in sorted(_ICON, reverse=True)
        if any(f.severity == level for f in result.findings)
    ]
    return f"{total} {plural} ({', '.join(by_level)})"


def _clean(text: str, limit: int) -> str:
    """Collapse whitespace, cap length, redact, and keep PR text from becoming Markdown.

    Code spans are paired the way CommonMark pairs them (a run of n backticks closes only
    at the next run of exactly n) and rebuilt with ``md_code``, which redacts their
    contents and picks a fence they cannot close. Every other stretch is redacted first
    and then has its inline Markdown and HTML characters backslash-escaped, so PR text
    cannot add links, images, emphasis or tags. A
    backtick run with no partner is escaped too, so it can never pair with a span added
    after this text.
    """
    text = " ".join(text.split())
    if len(text) > limit:
        text = text[: limit - 1] + "…"
    out: list[str] = []
    index = 0
    while index < len(text):
        if text[index] != "`":
            stop = text.find("`", index)
            stop = len(text) if stop < 0 else stop
            out.append(_escape_prose(text[index:stop]))
            index = stop
            continue
        run = len(text[index:]) - len(text[index:].lstrip("`"))
        close = _closing_run(text, index + run, run)
        if close < 0:
            out.append("\\`" * run)
            index += run
            continue
        # Rebuild the span: its contents are redacted and get a fence they cannot close.
        out.append(md_code(text[index + run : close]))
        index = close + run
    return "".join(out)


_PROSE_SPECIALS = re.compile(r"([\\*_\[\]!<>&~|])")


def _escape_prose(text: str) -> str:
    escaped = _PROSE_SPECIALS.sub(r"\\\1", redact_text(text))
    # A word joiner after `@` keeps GitHub from turning quoted `@user` or `@org/team` into a
    # mention that pings someone on every push; the text still reads the same.
    return escaped.replace("@", "@\u2060")


def _closing_run(text: str, start: int, length: int) -> int:
    position = start
    while True:
        found = text.find("`", position)
        if found < 0:
            return -1
        end = found
        while end < len(text) and text[end] == "`":
            end += 1
        if end - found == length:
            return found
        position = end
