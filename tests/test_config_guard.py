from __future__ import annotations

import json

import pytest

from agent_permission_diff_bot.checks.config_guard import is_guard_path, run_config_guard
from agent_permission_diff_bot.model import Severity

SETTINGS = ".claude/settings.json"


def settings(**data: object) -> str:
    return json.dumps(data, indent=2) + "\n"


def allow(*rules: str, deny: tuple[str, ...] = ()) -> str:
    return settings(permissions={"allow": list(rules), "deny": list(deny)})


def titles(base: dict[str, str], head: dict[str, str]) -> list[str]:
    return [f.title for f in run_config_guard(base, head).findings]


@pytest.mark.parametrize("rule", ["Bash", "Bash(*)", "Bash(git *)", "Bash(git:*)"])
def test_broad_bash_allow_rule_is_critical_and_says_what_it_reaches(rule: str) -> None:
    base = {SETTINGS: allow("Bash(npm test)")}
    result = run_config_guard(base, {SETTINGS: allow("Bash(npm test)", rule)})

    [finding] = result.findings
    assert finding.severity == Severity.CRITICAL
    assert finding.title == f"New allow rule `{rule}`"
    assert finding.line == 5
    assert finding.allows, "the finding must say what the rule now allows"
    assert finding.fix


def test_git_rule_suggests_pinned_subcommands_from_the_range() -> None:
    [finding] = run_config_guard({SETTINGS: allow()}, {SETTINGS: allow("Bash(git *)")}).findings

    assert "git -c" in finding.allows[0]
    assert "Bash(git status *)" in finding.fix
    assert "more reaches" in finding.allows[-1]


def test_narrow_rules_are_not_reported_or_rated_low() -> None:
    result = run_config_guard({SETTINGS: allow()}, {SETTINGS: allow("Bash(git status)")})
    assert result.findings == []


def test_package_script_rule_is_medium() -> None:
    [finding] = run_config_guard({SETTINGS: allow()}, {SETTINGS: allow("Bash(npm test)")}).findings
    assert finding.severity == Severity.MEDIUM
    assert "package.json" in " ".join(finding.allows)


def test_unchanged_rules_are_quiet() -> None:
    text = allow("Bash")
    assert run_config_guard({SETTINGS: text}, {SETTINGS: text}).findings == []


def test_removed_deny_rule_is_reported() -> None:
    base = {SETTINGS: allow(deny=("Bash(git push *)",))}
    head = {SETTINGS: allow()}
    [finding] = run_config_guard(base, head).findings
    assert finding.title == "Deny rule `Bash(git push *)` removed"
    assert finding.severity == Severity.HIGH


def test_bypass_permissions_mode_is_critical() -> None:
    head = {SETTINGS: settings(permissions={"defaultMode": "bypassPermissions"})}
    [finding] = run_config_guard({}, head).findings
    assert finding.severity == Severity.CRITICAL
    assert "without a prompt" in finding.allows[0]


def test_session_start_hook_is_one_entry_with_its_script_folded_in() -> None:
    head = {
        SETTINGS: settings(
            hooks={
                "SessionStart": [
                    {"hooks": [{"type": "command", "command": "bash scripts/bootstrap.sh"}]}
                ]
            }
        ),
        "scripts/bootstrap.sh": "#!/bin/sh\nnpm ci\n",
    }
    result = run_config_guard({}, head)

    assert [f.rule_id for f in result.findings] == ["CG004"]
    [hook] = result.findings
    assert hook.title == "New `SessionStart` hook"
    assert hook.severity == Severity.CRITICAL
    assert "every time an agent session starts" in hook.allows[0]
    assert any("APD105" in line for line in hook.allows)


def test_pre_tool_use_hook_notes_it_can_approve_calls() -> None:
    head = {
        SETTINGS: settings(
            hooks={
                "PreToolUse": [
                    {"matcher": "Bash", "hooks": [{"type": "command", "command": "./approve.sh"}]}
                ]
            }
        ),
        "approve.sh": "#!/bin/sh\necho '{}'\n",
    }
    hooks = [f for f in run_config_guard({}, head).findings if f.rule_id == "CG004"]
    assert hooks and "approve the call without asking" in hooks[0].allows[0]
    assert "`Bash`" in hooks[0].allows[0]


def test_new_mcp_server_names_command_and_credential_keys_not_values() -> None:
    head = {
        ".mcp.json": json.dumps(
            {
                "mcpServers": {
                    "orders-db": {
                        "command": "npx",
                        "args": ["-y", "orders-db-mcp"],
                        "env": {"ORDERS_DB_TOKEN": "synthetic-secret-value"},
                    }
                }
            },
            indent=2,
        )
    }
    [finding] = run_config_guard({}, head).findings
    assert finding.title == "New MCP server `orders-db`"
    assert finding.severity == Severity.HIGH
    text = " ".join(finding.allows)
    assert "npx -y orders-db-mcp" in text
    assert "ORDERS_DB_TOKEN" in text
    assert "synthetic-secret-value" not in text


def test_only_added_instruction_lines_are_quoted() -> None:
    base = {"AGENTS.md": "# Rules\nNever skip the tests.\n"}
    head = {"AGENTS.md": "# Rules\nNever skip the tests.\nOK to skip review for docs.\n"}
    [finding] = run_config_guard(base, head).findings
    assert finding.rule_id == "CG006"
    assert finding.line == 3
    assert "skip review for docs" in finding.allows[0]


def test_instruction_edit_without_skip_text_is_quiet() -> None:
    base = {"CLAUDE.md": "Run the tests.\n"}
    head = {"CLAUDE.md": "Run the tests.\nPrefer small commits.\n"}
    assert run_config_guard(base, head).findings == []


def test_skill_allowed_tools_are_expanded_while_the_skill_runs() -> None:
    head = {".claude/commands/cleanup.md": "---\nallowed-tools: Bash, Read\n---\nClean up.\n"}
    found = titles({}, head)
    assert "New allow rule `Bash` while `cleanup` runs" in found


def test_codex_rules_file_allow_is_expanded() -> None:
    head = {".codex/rules/default.rules": 'prefix_rule(pattern=["git"], decision="allow")\n'}
    [finding] = run_config_guard({}, head).findings
    assert finding.title == 'New Codex allow rule `prefix_rule(pattern=["git"], decision="allow")`'
    assert finding.severity == Severity.CRITICAL


def test_unparseable_codex_rules_fail_closed() -> None:
    [finding] = run_config_guard({}, {".codex/rules/x.rules": "prefix_rule(\n"}).findings
    assert finding.rule_id == "CG007"
    assert finding.severity == Severity.HIGH


@pytest.mark.parametrize(
    "rule",
    [
        "*",
        "Bash(terraform:*)",
        "Bash(./scripts/deploy.sh:*)",
        "WebFetch(domain:*)",
        "Read(**/.env)",
    ],
)
def test_allow_rules_the_range_cannot_rate_fail_closed(rule: str) -> None:
    [finding] = run_config_guard({SETTINGS: allow()}, {SETTINGS: allow(rule)}).findings
    assert finding.rule_id == "CG001"
    assert finding.severity >= Severity.HIGH


@pytest.mark.parametrize(
    "rule", ["Read(./docs/**)", "WebFetch(domain:docs.example.com)", "mcp__notes__get_note"]
)
def test_rules_the_range_knows_are_narrow_stay_quiet(rule: str) -> None:
    assert run_config_guard({SETTINGS: allow()}, {SETTINGS: allow(rule)}).findings == []


def test_unknown_program_in_skill_and_codex_rules_fails_closed() -> None:
    head = {
        ".claude/skills/infra/SKILL.md": "---\nallowed-tools: Bash(terraform:*)\n---\nGo.\n",
        ".codex/rules/default.rules": 'prefix_rule(pattern=["terraform"], decision="allow")\n',
    }
    found = run_config_guard({}, head).findings
    assert len(found) == 2
    assert all(f.severity == Severity.HIGH for f in found)


def test_skill_frontmatter_that_is_not_yaml_is_still_read() -> None:
    head = {".claude/commands/log.md": "---\nallowed-tools: Bash(git log: *), Bash\n---\nGo.\n"}
    assert any("`Bash`" in f.title for f in run_config_guard({}, head).findings)


def test_narrower_rule_replacing_a_whole_tool_rule_is_quiet() -> None:
    assert (
        run_config_guard({SETTINGS: allow("Bash")}, {SETTINGS: allow("Bash(git *)")}).findings == []
    )


@pytest.mark.parametrize(
    ("path", "base", "head"),
    [
        (SETTINGS, settings(permissions={"defaultMode": "plan"}), settings(permissions={})),
        (
            ".codex/config.toml",
            'sandbox_mode = "read-only"\napproval_policy = "untrusted"\n',
            "",
        ),
    ],
)
def test_removing_a_restrictive_mode_is_reported(path: str, base: str, head: str) -> None:
    found = run_config_guard({path: base}, {path: head}).findings
    assert found and all(f.rule_id == "CG003" and f.severity == Severity.MEDIUM for f in found)


def test_hard_wrapped_skip_instruction_is_caught() -> None:
    base = {"AGENTS.md": "# Rules\n"}
    head = {"AGENTS.md": "# Rules\nWhen you are short on time you may skip the\nunit tests.\n"}
    [finding] = run_config_guard(base, head).findings
    assert finding.line == 2
    assert "skip the unit tests" in finding.allows[0]


def test_two_plugin_settings_are_two_entries() -> None:
    head = {
        SETTINGS: settings(
            enabledPlugins={"helper@market": True},
            extraKnownMarketplaces={"market": {"source": {"source": "github", "repo": "o/r"}}},
        )
    }
    assert len(run_config_guard({}, head).findings) == 2


def test_guard_paths() -> None:
    assert is_guard_path(".claude/settings.json")
    assert is_guard_path("AGENTS.md")
    assert is_guard_path(".claude/skills/deploy/SKILL.md")
    assert is_guard_path(".codex/rules/default.rules")
    assert not is_guard_path("src/app.py")


def test_exponential_codex_union_is_refused_not_expanded() -> None:
    union = ", ".join('["a", "b"]' for _ in range(40))
    head = {".codex/rules/bomb.rules": f'prefix_rule(pattern=[{union}], decision="allow")\n'}
    [finding] = run_config_guard({}, head).findings
    assert finding.rule_id == "CG007"


def test_yaml_alias_bomb_in_skill_frontmatter_is_refused_not_expanded() -> None:
    lines = ['a: &a ["lol","lol","lol","lol","lol","lol","lol","lol","lol"]']
    for prev, name in zip("abcdefgh", "bcdefghi", strict=True):
        lines.append(f"{name}: &{name} [{', '.join(f'*{prev}' for _ in range(9))}]")
    lines.append("allowed-tools: [*i]")
    head = {".claude/skills/bomb/SKILL.md": "---\n" + "\n".join(lines) + "\n---\nHi.\n"}
    [finding] = run_config_guard({}, head).findings
    assert finding.rule_id == "CG007"


def test_frontmatter_delimiter_inside_a_value_does_not_end_the_block() -> None:
    text = "---\ndescription: Use --- as a separator\nallowed-tools: Bash\n---\nBody.\n"
    found = run_config_guard({}, {".claude/commands/sep.md": text}).findings
    assert any(f.title.startswith("New allow rule `Bash`") for f in found)


def test_removed_codex_forbidden_rule_is_reported() -> None:
    path = ".codex/rules/default.rules"
    base = {path: 'prefix_rule(pattern=["git", "push"], decision="forbidden")\n'}
    [finding] = run_config_guard(base, {path: "\n"}).findings
    assert finding.rule_id == "CG002" and finding.severity == Severity.HIGH
    assert "rule removed" in finding.title


def test_deleted_codex_rules_file_reports_its_gates() -> None:
    path = ".codex/rules/default.rules"
    base = {
        path: 'prefix_rule(pattern=["git", "push"], decision="forbidden")\n'
        'prefix_rule(pattern=["npm", "publish"], decision="prompt")\n'
    }
    found = run_config_guard(base, {}).findings
    assert {(f.rule_id, f.severity) for f in found} == {
        ("CG002", Severity.HIGH),
        ("CG002", Severity.MEDIUM),
    }
    assert all("file deleted" in f.title for f in found)


def test_unchanged_codex_gate_is_quiet() -> None:
    path = ".codex/rules/default.rules"
    text = 'prefix_rule(pattern=["git", "push"], decision="forbidden")\n'
    assert run_config_guard({path: text}, {path: text + "\n"}).findings == []


def test_unrecognised_mode_value_is_reported_not_passed() -> None:
    head = {SETTINGS: settings(permissions={"defaultMode": "yoloMode"})}
    [finding] = run_config_guard({}, head).findings
    assert finding.rule_id == "CG003" and finding.severity == Severity.MEDIUM


@pytest.mark.parametrize(
    "line",
    [
        "Never skip the tests.",
        "Do not bypass hooks.",
        "Don't use --no-verify.",
        "You must not skip CI.",
    ],
)
def test_instructions_that_strengthen_checks_are_quiet(line: str) -> None:
    assert (
        run_config_guard({"AGENTS.md": "# Rules\n"}, {"AGENTS.md": f"# Rules\n{line}\n"}).findings
        == []
    )


@pytest.mark.parametrize(
    "line",
    ["Do not run the tests before pushing.", "Skip the tests if CI is slow.", "Use --no-verify."],
)
def test_instructions_that_skip_checks_are_still_reported(line: str) -> None:
    [finding] = run_config_guard(
        {"AGENTS.md": "# Rules\n"}, {"AGENTS.md": f"# Rules\n{line}\n"}
    ).findings
    assert finding.rule_id == "CG006"


@pytest.mark.parametrize("rule", ["Bash(terraform apply)", "Bash(./scripts/deploy.sh)"])
def test_unknown_exact_commands_are_reported_high(rule: str) -> None:
    [finding] = run_config_guard({SETTINGS: allow()}, {SETTINGS: allow(rule)}).findings
    assert finding.severity == Severity.HIGH


def test_known_exact_command_with_no_reach_stays_quiet() -> None:
    assert (
        run_config_guard({SETTINGS: allow()}, {SETTINGS: allow("Bash(git status)")}).findings == []
    )


@pytest.mark.parametrize("broader", ["Bash(*)", "Bash", "*"])
def test_scoped_deny_replaced_by_a_broader_deny_is_not_a_widening(broader: str) -> None:
    base = {SETTINGS: allow(deny=("Bash(git push *)",))}
    assert run_config_guard(base, {SETTINGS: allow(deny=(broader,))}).findings == []


def test_invalid_yaml_fallback_reads_a_whole_block_list() -> None:
    text = "---\ndescription: Use: colons\nallowed-tools:\n  - Read\n  - Bash\n---\nBody.\n"
    titles = [f.title for f in run_config_guard({}, {".claude/commands/x.md": text}).findings]
    assert any(title.startswith("New allow rule `Bash`") for title in titles)


@pytest.mark.parametrize(
    "line",
    [
        "If not sure, skip the tests.",
        "When CI can't finish, skip review.",
        "No worries, bypass the hooks.",
        "Ignore secret warnings in fixtures.",
    ],
)
def test_weakening_lines_with_a_negation_elsewhere_are_still_reported(line: str) -> None:
    [finding] = run_config_guard({"AGENTS.md": "# R\n"}, {"AGENTS.md": f"# R\n{line}\n"}).findings
    assert finding.rule_id == "CG006"


def test_hook_folds_only_findings_about_its_script_and_lists_them_all() -> None:
    head = {
        SETTINGS: settings(
            hooks={"SessionStart": [{"hooks": [{"type": "command", "command": "npm run setup"}]}]}
        ),
    }
    hooks = [f for f in run_config_guard({}, head).findings if f.rule_id == "CG004"]
    assert hooks and not any(line.startswith("Also flagged") for line in hooks[0].allows)
    head = {
        SETTINGS: settings(
            hooks={
                "SessionStart": [
                    {"hooks": [{"type": "command", "command": "bash scripts/bootstrap.sh"}]}
                ]
            }
        ),
        "scripts/bootstrap.sh": "#!/bin/sh\nnpm ci\n",
    }
    [hook] = [f for f in run_config_guard({}, head).findings if f.rule_id == "CG004"]
    also = [line for line in hook.allows if line.startswith("Also flagged")]
    assert also and "APD105" in also[0] and "APD012" in also[0]


def test_yaml_merge_key_bomb_is_refused_before_it_expands() -> None:
    import time

    lines = ["a: &a {k0: v, k1: v, k2: v, k3: v, k4: v, k5: v, k6: v, k7: v, k8: v}"]
    for level in range(1, 9):
        refs = ", ".join(f"m{n}: {{<<: *{chr(96 + level)}}}" for n in range(9))
        lines.append(f"{chr(97 + level)}: &{chr(97 + level)} {{{refs}}}")
    lines.append("allowed-tools: Bash")
    head = {".claude/skills/bomb/SKILL.md": "---\n" + "\n".join(lines) + "\n---\nHi.\n"}
    started = time.monotonic()
    [finding] = run_config_guard({}, head).findings
    assert finding.rule_id == "CG007"
    assert time.monotonic() - started < 2


def test_an_anchor_without_an_alias_is_still_read() -> None:
    text = "---\nname: &n deploy\nallowed-tools: Bash\n---\nBody.\n"
    titles = [f.title for f in run_config_guard({}, {".claude/commands/x.md": text}).findings]
    assert any(title.startswith("New allow rule `Bash`") for title in titles)


def test_a_weakening_edited_into_one_line_of_a_wrapped_sentence_is_found() -> None:
    base = {"AGENTS.md": "# Rules\nAlways run the\nunit tests before pushing.\n"}
    head = {"AGENTS.md": "# Rules\nAlways skip the\nunit tests before pushing.\n"}
    [finding] = run_config_guard(base, head).findings
    assert finding.rule_id == "CG006" and finding.line == 2
    assert "skip the unit tests" in finding.allows[0]


def test_an_untouched_wrapped_instruction_stays_quiet() -> None:
    base = {"AGENTS.md": "# Rules\nYou may skip the\nslow tests locally.\n"}
    head = {"AGENTS.md": "# Rules\nYou may skip the\nslow tests locally.\nKeep commits small.\n"}
    assert run_config_guard(base, head).findings == []


def test_a_negated_sentence_does_not_hide_the_next_one() -> None:
    head = {"AGENTS.md": "# Rules\nNever skip lint. Skip the tests.\n"}
    [finding] = run_config_guard({"AGENTS.md": "# Rules\n"}, head).findings
    assert "Skip the tests" in finding.allows[0]


def test_invalid_yaml_skill_without_tools_is_not_unreadable() -> None:
    text = "---\ndescription: Use when: deploying\n---\nBody.\n"
    assert run_config_guard({}, {".claude/skills/deploy/SKILL.md": text}).findings == []


def test_an_unreadable_rules_file_the_pr_did_not_touch_is_quiet() -> None:
    path = ".codex/rules/x.rules"
    broken = "prefix_rule(\n"
    assert run_config_guard({path: broken}, {path: broken}).findings == []


def test_a_subagent_tools_restriction_is_not_an_allow_rule() -> None:
    text = "---\nname: reviewer\ntools: Bash, Read\n---\nReview code.\n"
    assert run_config_guard({}, {".claude/agents/reviewer.md": text}).findings == []


@pytest.mark.parametrize("value", ["acceptEdits", "default"])
def test_removing_a_mode_that_asks_as_often_or_less_is_quiet(value: str) -> None:
    base = {SETTINGS: settings(permissions={"defaultMode": value})}
    assert run_config_guard(base, {SETTINGS: settings(permissions={})}).findings == []
