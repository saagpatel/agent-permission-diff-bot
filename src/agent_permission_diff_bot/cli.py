from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from agent_permission_diff_bot.engine import build_report
from agent_permission_diff_bot.gating import evaluate_gate
from agent_permission_diff_bot.model import Severity
from agent_permission_diff_bot.policy import PolicyError, apply_policy_file
from agent_permission_diff_bot.reporting import (
    append_step_summary,
    render_markdown,
    write_json,
    write_markdown,
    write_sarif,
)
from agent_permission_diff_bot.simulate import (
    GitHubActionsLiveProbeOptions,
    build_simulation,
    list_simulation_probes,
    list_simulation_scenarios,
    render_simulation_markdown,
    write_simulation_json,
    write_simulation_markdown,
)
from agent_permission_diff_bot.sources import (
    changed_git_paths,
    read_dir_snapshot,
    read_git_snapshot,
)


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command == "diff":
        return _run_diff(args)
    if args.command == "simulate":
        return _run_simulate(args)
    parser.print_help()
    return 1


def _run_diff(args: argparse.Namespace) -> int:
    if args.repo:
        repo = Path(args.repo).resolve()
        if not args.base_ref or not args.head_ref:
            raise SystemExit("--repo requires --base-ref and --head-ref")
        paths = changed_git_paths(repo, args.base_ref, args.head_ref)
        base_label, base_files = read_git_snapshot(repo, args.base_ref, paths)
        head_label, head_files = read_git_snapshot(repo, args.head_ref, paths)
    else:
        if not args.base_dir or not args.head_dir:
            raise SystemExit("provide either --repo with refs or --base-dir and --head-dir")
        base_label, base_files = read_dir_snapshot(Path(args.base_dir).resolve())
        head_label, head_files = read_dir_snapshot(Path(args.head_dir).resolve())

    report = build_report(base_label, base_files, head_label, head_files)
    if args.policy:
        try:
            apply_policy_file(report, Path(args.policy))
        except PolicyError as exc:
            raise SystemExit(str(exc)) from exc
    threshold = Severity.parse(args.fail_on)
    report.gate = evaluate_gate(report, args.mode, threshold)
    if args.json:
        write_json(report, Path(args.json))
    if args.markdown:
        write_markdown(report, Path(args.markdown))
    if args.sarif:
        write_sarif(report, Path(args.sarif))
    if args.step_summary:
        append_step_summary(
            report,
            Path(args.step_summary_path) if args.step_summary_path else None,
        )
    if not args.json and not args.markdown and not args.sarif and not args.step_summary:
        print(render_markdown(report))

    return report.gate.exit_code


def _run_simulate(args: argparse.Namespace) -> int:
    if args.list_scenarios:
        print(json.dumps(list_simulation_scenarios(), indent=2, sort_keys=True))
        return 0
    if args.list_probes:
        print(json.dumps(list_simulation_probes(), indent=2, sort_keys=True))
        return 0
    report = build_simulation(
        scenarios=tuple(args.scenario or ()),
        probes=tuple(args.probe or ()),
        command=args.command_string,
        workflow_text=_read_optional_text(args.workflow),
        mcp_config_text=_read_optional_text(args.mcp_config),
        mcpaudit_json_text=_read_optional_text(args.mcpaudit_json),
        subagent_text=_read_optional_text(args.subagent),
        hook_policy_text=_read_optional_text(args.hook_policy),
        github_actions_probe_json_text=_read_optional_text(args.github_actions_probe_json),
        github_actions_live_options=_github_actions_live_options(args),
    )
    if args.json:
        write_simulation_json(report, Path(args.json))
    if args.markdown:
        write_simulation_markdown(report, Path(args.markdown))
    if not args.json and not args.markdown:
        print(render_simulation_markdown(report))
    return 0


def _read_optional_text(path: str | None) -> str | None:
    if not path:
        return None
    if path == "-":
        return sys.stdin.read()
    return Path(path).read_text(encoding="utf-8")


def _github_actions_live_options(
    args: argparse.Namespace,
) -> GitHubActionsLiveProbeOptions | None:
    if not args.github_actions_live:
        return None
    return GitHubActionsLiveProbeOptions(
        repository=args.github_repository,
        ref=args.github_ref,
        pull_number=args.github_pull_number,
        token_env=args.github_token_env,
        timeout_seconds=args.github_timeout,
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agent-permission-diff",
        description="Detect and explain changes to agent-facing permissions.",
    )
    subparsers = parser.add_subparsers(dest="command")
    diff = subparsers.add_parser("diff", help="compare two Git refs or two directories")
    diff.add_argument("--repo", help="Git repository to compare")
    diff.add_argument("--base-ref", help="Base Git ref")
    diff.add_argument("--head-ref", help="Head Git ref")
    diff.add_argument("--base-dir", help="Base directory snapshot")
    diff.add_argument("--head-dir", help="Head directory snapshot")
    diff.add_argument("--json", help="Write JSON report")
    diff.add_argument("--markdown", help="Write Markdown report")
    diff.add_argument("--sarif", help="Write SARIF 2.1.0 report")
    diff.add_argument(
        "--step-summary",
        action="store_true",
        help="Append Markdown to $GITHUB_STEP_SUMMARY when available.",
    )
    diff.add_argument(
        "--step-summary-path",
        help="Append step-summary Markdown to this path instead of $GITHUB_STEP_SUMMARY.",
    )
    diff.add_argument("--mode", choices=("observe", "warn", "enforce"), default="observe")
    diff.add_argument(
        "--policy",
        help=(
            "Optional YAML policy file with acknowledgement entries that keep findings "
            "visible but exclude matched findings from gate decisions."
        ),
    )
    diff.add_argument(
        "--fail-on",
        choices=("critical", "high", "medium", "low"),
        default="critical",
        help="Minimum severity that exits 2 in warn/enforce mode.",
    )

    simulate = subparsers.add_parser(
        "simulate",
        help="statically simulate what a proposed agent permission surface can do",
    )
    simulate.add_argument(
        "--command",
        dest="command_string",
        help="Proposed shell command string to classify.",
    )
    simulate.add_argument(
        "--workflow",
        help="Path to a GitHub Actions workflow snapshot or diff-like YAML snippet.",
    )
    simulate.add_argument(
        "--mcp-config",
        help="Path to an MCP config snippet. Use --mcpaudit-json for MCPAudit output.",
    )
    simulate.add_argument(
        "--mcpaudit-json",
        help="Path to MCPAudit JSON output to ingest as supplied static evidence.",
    )
    simulate.add_argument(
        "--subagent",
        help="Path to Claude subagent frontmatter or a subagent markdown file.",
    )
    simulate.add_argument(
        "--hook-policy",
        help="Path to a Codex/Claude hook-policy snapshot such as hooks.json or policy JSON.",
    )
    simulate.add_argument(
        "--scenario",
        action="append",
        choices=tuple(item["name"] for item in list_simulation_scenarios()),
        help="Run a built-in static scenario fixture. May be supplied more than once.",
    )
    simulate.add_argument(
        "--list-scenarios",
        action="store_true",
        help="List built-in static scenario fixtures as JSON and exit.",
    )
    simulate.add_argument(
        "--probe",
        action="append",
        help=(
            "Run an explicitly supplied live-read-only probe adapter. "
            "Currently supported: github-actions-readonly."
        ),
    )
    simulate.add_argument(
        "--list-probes",
        action="store_true",
        help="List supported live-read-only probe adapters as JSON and exit.",
    )
    simulate.add_argument(
        "--github-actions-probe-json",
        help=(
            "Path to a supplied GitHub Actions metadata JSON snapshot for "
            "--probe github-actions-readonly. No GitHub API calls are made."
        ),
    )
    simulate.add_argument(
        "--github-actions-live",
        action="store_true",
        help=(
            "Allow --probe github-actions-readonly to make explicit GET-only requests to "
            "api.github.com. Off by default."
        ),
    )
    simulate.add_argument(
        "--github-repository",
        help="Repository for --github-actions-live in owner/repo form.",
    )
    simulate.add_argument(
        "--github-ref",
        help="Branch, tag, or SHA for --github-actions-live metadata reads.",
    )
    simulate.add_argument(
        "--github-pull-number",
        type=int,
        help=(
            "Optional pull request number. When --github-ref is omitted, live mode resolves "
            "the PR head SHA with an extra GET request to api.github.com."
        ),
    )
    simulate.add_argument(
        "--github-token-env",
        help=(
            "Optional environment variable name containing a GitHub token. The simulator "
            "reports only the env var name, never the token value."
        ),
    )
    simulate.add_argument(
        "--github-timeout",
        type=float,
        default=10.0,
        help="Timeout in seconds for explicit GitHub read-only probe requests. Max: 30.",
    )
    simulate.add_argument("--json", help="Write JSON simulation output")
    simulate.add_argument("--markdown", help="Write Markdown simulation output")
    return parser


if __name__ == "__main__":
    sys.exit(main())
