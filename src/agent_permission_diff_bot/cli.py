from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from agent_permission_diff_bot.engine import build_report
from agent_permission_diff_bot.gating import evaluate_gate
from agent_permission_diff_bot.model import Severity
from agent_permission_diff_bot.persistence import snapshot_hook_references
from agent_permission_diff_bot.policy import PolicyError, apply_policy_file
from agent_permission_diff_bot.reporting import (
    append_step_summary,
    render_markdown,
    write_json,
    write_markdown,
    write_sarif,
)
from agent_permission_diff_bot.server_card_diff import build_server_card_report
from agent_permission_diff_bot.server_card_model import SourceSnapshot
from agent_permission_diff_bot.server_card_reporting import (
    render_server_card_human,
    write_server_card_human,
    write_server_card_json,
    write_server_card_markdown,
    write_server_card_sarif,
)
from agent_permission_diff_bot.server_card_schema import (
    explain_server_card_schema,
    server_card_json_schema,
    validate_server_card_json,
)
from agent_permission_diff_bot.server_card_sources import (
    ServerCardInputError,
    read_server_card_directory,
    read_server_card_file,
    read_server_card_git_ref,
)
from agent_permission_diff_bot.simulate import (
    GitHubActionsLiveProbeOptions,
    build_simulation,
    explain_simulation_schema,
    list_simulation_probes,
    list_simulation_scenarios,
    render_simulation_markdown,
    simulation_json_schema,
    validate_simulation_json,
    write_simulation_json,
    write_simulation_json_summary,
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
    if args.command in {"server-card-diff", "mcp-server-card-diff"}:
        return _run_server_card_diff(args)
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

    # Read the same referenced paths at both ends so an existing payload stays existing.
    references = snapshot_hook_references(base_files) | snapshot_hook_references(head_files)
    if references:
        if args.repo:
            base_label, base_files = read_git_snapshot(repo, args.base_ref, paths, references)
            head_label, head_files = read_git_snapshot(repo, args.head_ref, paths, references)
        else:
            base_label, base_files = read_dir_snapshot(Path(args.base_dir), references)
            head_label, head_files = read_dir_snapshot(Path(args.head_dir), references)

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
    if args.explain_schema:
        print(json.dumps(explain_simulation_schema(), indent=2, sort_keys=True))
        return 0
    if args.json_schema:
        print(json.dumps(simulation_json_schema(args.json_schema), indent=2, sort_keys=True))
        return 0
    if args.validate_json:
        payload = json.loads(_read_optional_text(args.validate_json) or "null")
        result = validate_simulation_json(payload, args.schema)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["valid"] else 2
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
    if args.json_summary:
        write_simulation_json_summary(report, Path(args.json_summary))
    if args.markdown:
        write_simulation_markdown(report, Path(args.markdown))
    if not args.json and not args.json_summary and not args.markdown:
        print(render_simulation_markdown(report))
    return 0


def _run_server_card_diff(args: argparse.Namespace) -> int:
    if args.explain_schema:
        print(json.dumps(explain_server_card_schema(), indent=2, sort_keys=True))
        return 0
    if args.json_schema:
        print(json.dumps(server_card_json_schema(args.json_schema), indent=2, sort_keys=True))
        return 0
    if args.validate_json:
        payload = json.loads(_read_optional_text(args.validate_json) or "null")
        result = validate_server_card_json(payload, args.schema)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["valid"] else 2
    try:
        base, head = _read_server_card_inputs(args)
    except ServerCardInputError as exc:
        raise SystemExit(str(exc)) from exc
    report = build_server_card_report(
        base,
        head,
        mode=args.mode,
        fail_on=Severity.parse(args.fail_on),
    )
    if args.json:
        write_server_card_json(report, Path(args.json))
    if args.human:
        write_server_card_human(report, Path(args.human))
    if args.markdown:
        write_server_card_markdown(report, Path(args.markdown))
    if args.sarif:
        write_server_card_sarif(report, Path(args.sarif))
    if not any((args.json, args.human, args.markdown, args.sarif)):
        print(render_server_card_human(report), end="")
    return report.gate.exit_code if report.gate is not None else 0


def _read_server_card_inputs(
    args: argparse.Namespace,
) -> tuple[SourceSnapshot, SourceSnapshot]:
    card_paths = tuple(args.card_path or ())
    modes = sum(
        bool(value)
        for value in (
            args.repo,
            args.base_file or args.head_file,
            args.base_dir or args.head_dir,
        )
    )
    if modes != 1:
        raise ServerCardInputError(
            "provide exactly one input mode: --repo with refs, --base-file/--head-file, "
            "or --base-dir/--head-dir"
        )
    if args.repo:
        if not args.base_ref or not args.head_ref:
            raise ServerCardInputError("--repo requires --base-ref and --head-ref")
        repo = Path(args.repo)
        base = read_server_card_git_ref(repo, args.base_ref, card_paths=card_paths)
        head = read_server_card_git_ref(repo, args.head_ref, card_paths=card_paths)
        if card_paths and not base.cards and not head.cards:
            selected = ", ".join(card_paths)
            raise ServerCardInputError(
                f"explicit server-card path(s) not found in either Git ref: {selected}"
            )
        return (
            base,
            head,
        )
    if args.base_file or args.head_file:
        if not args.base_file or not args.head_file:
            raise ServerCardInputError("file mode requires --base-file and --head-file")
        return (
            read_server_card_file(Path(args.base_file), label=args.base_label),
            read_server_card_file(Path(args.head_file), label=args.head_label),
        )
    if not args.base_dir or not args.head_dir:
        raise ServerCardInputError("directory mode requires --base-dir and --head-dir")
    return (
        read_server_card_directory(
            Path(args.base_dir), label=args.base_label, card_paths=card_paths
        ),
        read_server_card_directory(
            Path(args.head_dir), label=args.head_label, card_paths=card_paths
        ),
    )


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
        "--explain-schema",
        action="store_true",
        help=(
            "Print machine-readable simulator contract metadata as JSON and exit. "
            "No simulation inputs or probes are executed."
        ),
    )
    simulate.add_argument(
        "--json-schema",
        choices=("summary", "full", "contract"),
        help=(
            "Print a JSON Schema for a simulator output shape and exit. "
            "No simulation inputs or probes are executed."
        ),
    )
    simulate.add_argument(
        "--validate-json",
        help=(
            "Validate an existing simulator JSON artifact against --schema and exit. "
            "Use '-' to read from stdin."
        ),
    )
    simulate.add_argument(
        "--schema",
        choices=("summary", "full", "contract"),
        default="summary",
        help="Simulator JSON schema to use with --validate-json. Default: summary.",
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
    simulate.add_argument(
        "--json-summary",
        help=(
            "Write compact JSON simulation summary with capabilities, risk facets, and "
            "live-probe-needed gaps."
        ),
    )
    simulate.add_argument("--markdown", help="Write Markdown simulation output")

    server_card = subparsers.add_parser(
        "server-card-diff",
        aliases=("mcp-server-card-diff",),
        help="compare declared MCP Registry metadata or server-card snapshots offline",
    )
    server_card.add_argument("--repo", help="Git repository containing both snapshots")
    server_card.add_argument("--base-ref", help="Base Git ref (local objects only; no fetch)")
    server_card.add_argument("--head-ref", help="Head Git ref (local objects only; no fetch)")
    server_card.add_argument("--base-file", help="Explicit base metadata JSON file")
    server_card.add_argument("--head-file", help="Explicit head metadata JSON file")
    server_card.add_argument("--base-dir", help="Base directory containing server cards")
    server_card.add_argument("--head-dir", help="Head directory containing server cards")
    server_card.add_argument("--base-label", help="Stable base label for file/directory input")
    server_card.add_argument("--head-label", help="Stable head label for file/directory input")
    server_card.add_argument(
        "--card-path",
        action="append",
        help=(
            "Relative card path for directory or Git-ref input. May be repeated; otherwise "
            "server.json, mcp-server.json, and *.server.json are discovered."
        ),
    )
    server_card.add_argument("--human", help="Write plain-text human report")
    server_card.add_argument("--json", help="Write versioned JSON drift report")
    server_card.add_argument("--markdown", help="Write Markdown drift report")
    server_card.add_argument("--sarif", help="Write SARIF 2.1.0 drift report")
    server_card.add_argument("--mode", choices=("observe", "warn", "enforce"), default="observe")
    server_card.add_argument(
        "--fail-on",
        choices=("critical", "high", "medium", "low"),
        default="critical",
        help="Minimum severity that exits 2 in warn/enforce mode.",
    )
    server_card.add_argument(
        "--explain-schema",
        action="store_true",
        help="Print static contract metadata and exit without reading inputs.",
    )
    server_card.add_argument(
        "--json-schema",
        choices=("report", "contract"),
        help="Print a JSON Schema and exit without reading inputs.",
    )
    server_card.add_argument(
        "--validate-json",
        help="Validate an existing report or contract artifact offline; '-' reads stdin.",
    )
    server_card.add_argument(
        "--schema",
        choices=("report", "contract"),
        default="report",
        help="Schema used with --validate-json. Default: report.",
    )
    return parser


if __name__ == "__main__":
    sys.exit(main())
