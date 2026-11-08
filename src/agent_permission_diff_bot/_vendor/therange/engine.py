"""Expand each rule into the capabilities it lets through."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass

from .claude_rules import parse_command_pattern
from .kb import Capability, KnowledgeBase
from .model import (
    SEVERITY_ORDER,
    CommandRule,
    Finding,
    GateFinding,
    Posture,
    Rule,
    RuleReport,
    Severity,
)
from .sources import CLAUDE_PERMISSIONS_DOC, CODEX_RULES_DOC

_PY_VERSIONED = re.compile(r"^(python3?)(\.\d+)*$")
_WRITE_VERBS = ("create", "delete", "update", "edit", "write", "execute", "exec", "send", "merge", "push", "drop", "remove", "upload", "apply", "post", "publish", "set_", "add_", "move", "rename", "archive", "deploy", "run")
_SECRET_HINTS = (".ssh", ".aws", ".gnupg", ".netrc", ".npmrc", ".pypirc", "credentials", "secrets", "Keychains", ".env", "auth.json", ".tokens", ".config/gh", ".kube", "gcloud", "/op/")


def normalize_program(word: str) -> str:
    base = os.path.basename(word)
    m = _PY_VERSIONED.match(base)
    return m.group(1) if m else base


def _normalized(words: tuple[str, ...]) -> tuple[str, ...]:
    return (normalize_program(words[0]), *words[1:]) if words else words


def _trigger_hit(word: str, trigger: str) -> bool:
    if word == trigger or word.startswith(trigger + "="):
        return True
    # Short options with an attached value: -Opager, -xcmd.
    return len(trigger) == 2 and trigger.startswith("-") and not trigger.startswith("--") and word.startswith(trigger) and len(word) > 2


def _finding(cap: Capability, agent: str) -> Finding:
    return Finding(
        capability_id=cap.id,
        severity=cap.severity,  # type: ignore[arg-type]
        title=cap.title,
        explain=cap.explain,
        example=cap.example,
        narrower=cap.narrower,
        doc=cap.doc,
        effect=cap.effect,
        mitigated_by=cap.claude_mitigated if agent == "claude" else "",
    )


def _reaches_prefix(cmd: CommandRule, path: tuple[str, ...], cap: Capability) -> bool:
    """Can a command matching this prefix rule carry the capability at `path`?"""
    fixed = _normalized(cmd.fixed)
    # With no whole words fixed, the partial word is the program name.
    partial = cmd.partial if fixed else normalize_program(cmd.partial) if cmd.partial else ""
    n = len(fixed)
    if len(path) >= n and path[:n] == fixed:
        if not partial:
            return True
        if len(path) > n:
            return path[n].startswith(partial)
        # The next word after the path must start with `partial`. Options that
        # may appear anywhere later are still reachable after that word.
        if cap.kind == "any" or cap.position == "after":
            return True
        return any(t.startswith(partial) for t in cap.triggers)
    if len(path) < n and fixed[: len(path)] == path:
        if cap.position == "after":
            return True
        if cap.position == "subcommand" and cap.kind == "flag":
            # The rule pins the verb; it reaches the capability only if that verb is a trigger.
            return fixed[len(path)] in cap.triggers
        if cap.position == "subcommand":
            return True
    return False


def _implicit_script(cmd: CommandRule, cap: Capability) -> bool:
    """pnpm-style runners treat an unknown command name as a package script."""
    if not cap.implicit_after:
        return False
    words = _normalized(cmd.exact if cmd.shape == "exact" else cmd.fixed)
    if not words:
        return False
    if words[0] not in cap.implicit_after:
        return False
    nxt = words[1] if len(words) > 1 else (cmd.partial if cmd.shape != "exact" else "")
    return bool(nxt) and not nxt.startswith("-") and nxt not in cap.builtins


def _reaches_exact(words: tuple[str, ...], path: tuple[str, ...], cap: Capability) -> bool:
    words = _normalized(words)
    if len(words) < len(path) or words[: len(path)] != path:
        return False
    rest = words[len(path) :]
    if cap.kind == "any":
        if cap.exact == "script-file":
            return False  # handled by _script_file_finding
        return True
    if cap.position == "before-subcommand":
        return bool(rest) and any(_trigger_hit(rest[0], t) for t in cap.triggers)
    if cap.position == "subcommand":
        return bool(rest) and rest[0] in cap.triggers
    return any(_trigger_hit(w, t) for w in rest for t in cap.triggers)


def _script_file_finding(words: tuple[str, ...], kb: KnowledgeBase) -> Finding | None:
    words = _normalized(words)
    if not words:
        return None
    for cap in kb.capabilities:
        if cap.kind != "any" or cap.exact != "script-file":
            continue
        if not any(path == words[:1] for path in cap.paths):
            continue
        rest = words[1:]
        if not rest or rest[0] in ("-c", "-e", "-m", "--eval", "-p"):
            return None
        script = next((w for w in rest if not w.startswith("-")), "")
        if not script:
            return None
        return Finding(
            capability_id="exact.script-file",
            severity="low",
            title=f"Runs a fixed script file ({os.path.basename(script)})",
            explain=(
                "The command is pinned exactly, so the rule cannot be stretched. It is exactly as safe as the script file: "
                "whatever can edit that file decides what this allowed command does."
            ),
            example=" ".join(words),
            narrower="Keep it; make sure the script lives where the agent does not edit it.",
            doc=cap.doc,
            effect="exec",
        )
    return None


def analyze_command(cmd: CommandRule, agent: str, kb: KnowledgeBase) -> list[Finding]:
    if cmd.shape == "any" or (not cmd.fixed and not cmd.partial):
        what = "every command" if cmd.shape == "any" else f"any program, as long as the command ends with `{cmd.suffix}`"
        return [
            Finding(
                capability_id="rule.any-command",
                severity="critical",
                title=f"Matches {what}",
                explain=(
                    "The wildcard stands in for the program itself, so the rule approves any command. "
                    "A required suffix does not help: `bash -c 'anything' --version` still ends with `--version`."
                    if cmd.shape != "any"
                    else "No program is named, so the rule approves any shell command."
                ),
                example="bash -c 'touch /tmp/proof'" + (f" {cmd.suffix}" if cmd.suffix else ""),
                narrower="Name each command the work needs.",
                doc=CLAUDE_PERMISSIONS_DOC if agent == "claude" else CODEX_RULES_DOC,
                effect="exec",
            )
        ]
    # Local patch: an option right after the program (`git -C . *`, `git -c*`) can be
    # followed by any other global option and any subcommand, so the rule reaches what
    # the bare program reaches. Option arity is unknown, so stay conservative.
    if cmd.shape != "exact" and cmd.fixed and (
        (len(cmd.fixed) >= 2 and cmd.fixed[1].startswith("-"))
        or (len(cmd.fixed) == 1 and cmd.partial.startswith("-"))
    ):
        cmd = CommandRule(shape="prefix", fixed=cmd.fixed[:1])
    findings: list[Finding] = []
    seen: set[str] = set()
    for cap in kb.capabilities:
        hits = [_reaches_exact(cmd.exact, p, cap) if cmd.shape == "exact" else _reaches_prefix(cmd, p, cap) for p in cap.paths]
        for hit in [any(hits) or _implicit_script(cmd, cap)]:
            if hit and cap.id not in seen:
                seen.add(cap.id)
                findings.append(_finding(cap, agent))
    if cmd.shape == "exact":
        script = _script_file_finding(cmd.exact, kb)
        if script:
            findings.append(script)
    elif not findings:
        program = normalize_program((cmd.fixed or (cmd.partial,))[0])
        if program not in kb.programs():
            findings.append(
                Finding(
                    capability_id="kb.unknown",
                    severity="info",
                    title=f"`{program}` is not in the knowledge base",
                    explain="No known subcommand or flag of this program runs other programs or writes outside the project, but the knowledge base does not cover it. Check its manual for exec, output-file or config options.",
                    example="",
                    narrower="",
                    doc="",
                    effect="unknown",
                )
            )
    findings.sort(key=lambda f: SEVERITY_ORDER[f.effective_severity])
    return findings


def _analyze_tool(rule: Rule) -> list[Finding]:
    tool, spec = rule.tool, rule.specifier
    doc = CLAUDE_PERMISSIONS_DOC

    def one(cid: str, sev: Severity, title: str, explain: str, narrower: str = "", effect: str = "") -> list[Finding]:
        return [Finding(capability_id=cid, severity=sev, title=title, explain=explain, example="", narrower=narrower, doc=doc, effect=effect or cid)]

    if tool in ("*",) or (tool.endswith("*") and not re.match(r"^mcp__[^*]+__", tool)):
        return one(
            "rule.unanchored-glob",
            "info",
            "Has no effect as an allow rule",
            "Allow rules accept tool-name globs only after a literal `mcp__<server>__` prefix; an unanchored glob is skipped.",
            "Delete it, or name the server.",
            "none",
        )
    if tool in ("Edit", "Write", "NotebookEdit", "MultiEdit"):
        if spec is None or spec.strip() in ("", "**", "/**", "//**", "~/**"):
            verb = "Writes" if tool == "Write" else "Edits"
            return one(
                "file.write-any",
                "high",
                f"{verb} any file without asking",
                "With no path, or a root-wide pattern, the rule covers files outside the project too: shell profiles, LaunchAgents, git hooks, other repositories.",
                f"Scope it to the project, such as `{tool}(./src/**)`, or set permissions.blockWritesOutsideWorkingDirectories.",
                "write",
            )
        if spec.startswith(("//", "~")):
            sev: Severity = "high" if any(h in spec for h in _SECRET_HINTS) else "medium"
            return one("file.write-outside", sev, "Edits files outside the project", f"`{spec}` is anchored outside the working directory.", "Scope edits to the project where possible.", "write")
        return one("file.write-scoped", "low", "Edits files in a scoped path", f"Writes are limited to `{spec}`.", "", "write")
    if tool == "Glob" and spec is None:
        return one("file.list-any", "low", "Lists file names anywhere without asking", "Glob returns paths, not contents, but a bare rule covers directories outside the project.", "", "read")
    if tool in ("Read", "Glob", "Grep"):
        if spec is None:
            return one("file.read-any", "medium", f"{'Searches' if tool == 'Grep' else 'Reads'} any file without asking", "Reads inside the working directories are free already; a bare rule extends that to every path, including credential files not covered by a deny rule.", "Scope it, such as `Read(~/notes/**)`.", "secret")
        if spec.startswith(("//", "~")) and (spec.rstrip("/*") in ("", "~", "/") or any(h in spec for h in _SECRET_HINTS)):
            return one("file.read-wide", "medium", "Reads a wide or sensitive path", f"`{spec}` covers your home directory or a credential location.", "Narrow the path.", "secret")
        return one("file.read-scoped", "info", "Reads a scoped path", f"Reads are limited to `{spec}`.", "", "read")
    if tool == "WebFetch":
        if spec is None or not spec.startswith("domain:"):
            return one("web.fetch-any", "medium", "Fetches any URL without asking", "Any domain means data can leave in a query string to a host you never chose.", "Use `WebFetch(domain:example.com)` per domain.", "network")
        return one("web.fetch-domain", "info", f"Fetches from {spec.removeprefix('domain:')}", "Scoped to one domain.", "", "network")
    if tool.startswith("mcp__"):
        parts = tool.split("__")
        if len(parts) == 2 or (len(parts) >= 3 and parts[2] in ("", "*")):
            server = parts[1]
            return one("mcp.server-wide", "medium", f"Every tool of the `{server}` MCP server", "A server-wide rule covers write tools as well as reads, and any tool the server adds in a later version.", f"List the read tools you use, such as `mcp__{server}__get_*` or exact names.", "publish")
        name = "__".join(parts[2:])
        if any(v in name.lower() for v in _WRITE_VERBS):
            return one("mcp.write-tool", "medium", f"Approves the write-capable MCP tool `{name}`", "The tool name suggests it changes state.", "Confirm it is meant to run without a prompt.", "publish")
        return one("mcp.tool", "info", f"Approves the MCP tool `{name}`", "A single, named tool.", "", "read")
    if tool in ("Skill", "Agent", "Task", "AskUserQuestion", "TodoWrite", "ToolSearch", "WebSearch", "LSP"):
        return one("tool.benign", "info", f"`{tool}` tool", "Does not by itself run commands or write files.", "", "none")
    if rule.source.kind.endswith("allowed-tools") and not tool[:1].isupper():
        return one("tool.unknown-name", "info", f"`{tool}` names no built-in tool", "Plugin skill entries without an `mcp__` prefix do not name a Claude Code tool as written.", "", "none")
    return one("tool.other", "info", f"`{tool}`", "Not analysed by this slice.", "", "unknown")


def analyze_rule(rule: Rule, kb: KnowledgeBase) -> list[Finding]:
    if rule.command is not None:
        return analyze_command(rule.command, rule.agent, kb)
    return _analyze_tool(rule)


# --- suggestions -------------------------------------------------------------


def _format_rule(agent: str, text: str) -> str:
    if agent == "claude":
        return f"`Bash({text})`"
    words = text.removesuffix(" *").split()
    return "`prefix_rule(pattern=[" + ", ".join(f'"{w}"' for w in words) + "])`"


@dataclass
class Suggestion:
    text: str
    residual: list[tuple[str, Finding]]


def suggest(rule: Rule, findings: list[Finding], kb: KnowledgeBase) -> Suggestion:
    serious = [f for f in findings if SEVERITY_ORDER[f.effective_severity] <= SEVERITY_ORDER["medium"]]
    if not serious:
        return Suggestion("Keep as is.", [])
    cmd = rule.command
    if cmd is not None and cmd.shape != "exact" and (cmd.fixed or cmd.partial):
        fixed = _normalized(cmd.fixed)
        keys = [" ".join((*fixed, cmd.partial)).strip()] if cmd.partial else []
        keys.append(" ".join(fixed))
        pins = next((kb.pins[k] for k in keys if k in kb.pins), None)
        if pins:
            residual: list[tuple[str, Finding]] = []
            for pin in pins:
                # Local patch: a Codex suggestion is emitted as a prefix_rule, which also
                # matches trailing arguments, so rate it as a prefix, not an exact command.
                pin_rule = (
                    parse_command_pattern(pin)
                    if rule.agent == "claude"
                    else CommandRule(shape="prefix", fixed=tuple(pin.removesuffix(" *").split()))
                )
                for f in analyze_command(pin_rule, rule.agent, kb):
                    if SEVERITY_ORDER[f.effective_severity] <= SEVERITY_ORDER["medium"]:
                        residual.append((pin, f))
            text = "Replace with " + ", ".join(_format_rule(rule.agent, p) for p in pins) + "."
            if any(f.effect == "publish" for f in serious) and rule.decision == "allow":
                text += " Keep publishing verbs on prompt."
            return Suggestion(text, residual)
    tips = []
    for f in serious:
        if f.narrower and f.narrower not in tips:
            tips.append(f.narrower)
    return Suggestion(" ".join(tips[:3]) or "Name the specific commands this needs.", [])


# --- whole inventory ---------------------------------------------------------


def build_reports(rules: list[Rule], postures: list[Posture], kb: KnowledgeBase) -> list[RuleReport]:
    live = {p.agent: p for p in postures}
    reports: list[RuleReport] = []
    for rule in rules:
        if rule.decision != "allow":
            continue
        findings = analyze_rule(rule, kb)
        sugg = suggest(rule, findings, kb)
        posture = live.get(rule.agent)
        is_live = posture.allow_rules_live if posture else True
        reason = "" if is_live else f"latent: {posture.summary.split(':')[0]}" if posture else ""
        if rule.source.kind.endswith("allowed-tools"):
            reason = (reason + "; " if reason else "") + "only while that skill or command runs"
        reports.append(
            RuleReport(rule=rule, findings=findings, suggestion=sugg.text, residual=sugg.residual, live=is_live, live_reason=reason)
        )
    reports.sort(key=lambda r: (SEVERITY_ORDER[r.worst], r.rule.source.label, r.rule.raw))
    return reports


def gate_findings(rules: list[Rule], kb: KnowledgeBase) -> list[GateFinding]:
    """Deny and ask rules that another spelling of the same command gets past."""
    out: list[GateFinding] = []
    bash_gates = [r for r in rules if r.decision in ("ask", "deny") and r.command is not None and r.command.fixed]
    for rule in bash_gates:
        cmd = rule.command
        assert cmd is not None
        fixed = _normalized(cmd.fixed)
        program = fixed[0]
        ip = kb.interpose.get(program)
        if ip and len(fixed) > ip.after_words and (not ip.only or any(" ".join(fixed).startswith(o) for o in ip.only)):
            spelled = " ".join((*cmd.fixed[: ip.after_words], ip.flag, *cmd.fixed[ip.after_words :]))
            reached = [c for c in kb.capabilities if any(_reaches_exact(fixed, p, c) for p in c.paths)]
            sev: Severity = "high" if any(c.effect in ("publish", "destructive", "exec") and c.severity in ("critical", "high") for c in reached) else "medium"
            out.append(
                GateFinding(
                    rule=rule,
                    severity=sev,
                    title=f"A flag before the subcommand gets past `{rule.raw}`",
                    bypass=spelled + " ...",
                    explain=(
                        f"The rule only matches commands that start with `{' '.join(cmd.fixed)}`. `{program}` accepts "
                        f"`{ip.flag}` in front of the subcommand, so the same action spelled that way is not "
                        + ("asked about." if rule.decision == "ask" else "denied.")
                    ),
                    doc=ip.doc,
                    verified=ip.verified,
                )
            )
        elif len(cmd.fixed) >= 2 and (cmd.fixed[1].startswith("-") or cmd.fixed[1].isdigit()):
            out.append(
                GateFinding(
                    rule=rule,
                    severity="low",
                    title=f"`{rule.raw}` pins an argument, so reordered flags get past it",
                    bypass=_reorder_example(cmd.fixed),
                    explain="Rules that try to constrain arguments are fragile: an extra or reordered flag changes the text the rule sees.",
                    doc=CLAUDE_PERMISSIONS_DOC,
                    verified="Documented warning; spelling not executed.",
                )
            )
    if bash_gates:
        claude_gates = [r for r in bash_gates if r.agent == "claude"]
        if claude_gates:
            sample = claude_gates[0]
            assert sample.command is not None
            prog = sample.command.fixed[0]
            out.append(
                GateFinding(
                    rule=sample,
                    severity="medium",
                    title=f"All {len(claude_gates)} Bash ask/deny rules miss the absolute-path and `sh -c` forms",
                    bypass=f"/usr/bin/env {prog} ...   or   sh -c '{prog} ...'",
                    explain="A Bash rule matches the command text after wrapper stripping, not the program. The same program run by full path or inside `sh -c` is not matched, so these rules are guardrails, not a boundary. A PreToolUse hook or the sandbox is the boundary.",
                    doc=CLAUDE_PERMISSIONS_DOC + "#what-a-bash-rule-doesnt-match",
                    verified="Documented by Claude Code.",
                )
            )
    file_denies = [r for r in rules if r.agent == "claude" and r.decision == "deny" and r.tool in ("Read", "Edit")]
    if file_denies:
        sensitive = [r for r in file_denies if r.specifier and any(h in r.specifier for h in _SECRET_HINTS)]
        out.append(
            GateFinding(
                rule=(sensitive or file_denies)[0],
                severity="high" if sensitive else "medium",
                title=f"{len(file_denies)} Read/Edit deny rules do not cover scripts that open files themselves",
                bypass="python3 -c 'print(open(PATH).read())'",
                explain=(
                    "Read and Edit deny rules cover Claude's file tools, recognised file commands in Bash (cat, head, tail, sed, tee) "
                    "and redirect targets, but not an interpreter or other subprocess that opens the file itself. "
                    f"{len(sensitive)} of these rules protect credential locations."
                ),
                doc=CLAUDE_PERMISSIONS_DOC + "#what-read-and-edit-rules-cover",
                verified="Documented by Claude Code; not executed against real credential paths.",
            )
        )
    out.sort(key=lambda g: SEVERITY_ORDER[g.severity])
    return out


def _reorder_example(fixed: tuple[str, ...]) -> str:
    prog, rest = fixed[0], list(fixed[1:])
    if rest and rest[0].startswith("-") and len(rest[0]) > 2 and not rest[0].startswith("--"):
        flags = rest[0][1:]
        rest[0] = "-" + flags[::-1]
        return " ".join((prog, *rest))
    return " ".join((prog, "-R" if prog in ("chmod", "chown") else "-v", *rest))
