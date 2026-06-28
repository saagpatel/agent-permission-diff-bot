# Agent Permission Diff Bot

[![CI](https://github.com/saagpatel/agent-permission-diff-bot/actions/workflows/ci.yml/badge.svg)](https://github.com/saagpatel/agent-permission-diff-bot/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Agent Permission Diff Bot detects and explains changes to agent-facing permissions in
pull requests. It is a semantic correlator, not just a config linter: the useful signal is
when a PR changes what an agent can read, write, deploy, reach, or trust.

The first dogfood target is local CLI usage against Git refs or two checked-out trees,
with a composite GitHub Action for pull request scanning.

## Current Surfaces

- MCP and Copilot MCP config: `mcpServers`, `tools`, `env`, `headers`, `url`, `command`,
  and launch args.
- GitHub Actions: token permissions, OIDC, runner labels, trigger context, environments,
  secrets/env references, and deploy/publish actions.
- Egress policy: `allow_hosts`, `allow_connectors`, `network_name_globs`, and related
  policy keys.
- Agent instructions: `AGENTS.md`, `CLAUDE.md`, Copilot instructions, Cursor rules, and
  Windsurf rules.

## Installation

**Python >= 3.11 required.**

Install directly from GitHub (no PyPI release yet):

```bash
pip install git+https://github.com/saagpatel/agent-permission-diff-bot.git@v0.4.0
```

Or pin to a specific tag for reproducible installs:

```bash
pip install "git+https://github.com/saagpatel/agent-permission-diff-bot.git@v0.4.0"
```

## Usage

Compare two Git refs:

```bash
agent-permission-diff diff --repo . --base-ref origin/main --head-ref HEAD
```

Compare two directories:

```bash
agent-permission-diff diff --base-dir /tmp/base --head-dir /tmp/head --markdown report.md
```

Emit machine-readable output:

```bash
agent-permission-diff diff \
  --repo . \
  --base-ref origin/main \
  --head-ref HEAD \
  --json report.json \
  --sarif report.sarif
```

Run a static no-credential, no-network permission simulation before executing a command or
workflow:

```bash
agent-permission-diff simulate \
  --command 'gh pr create --repo saagpatel/example' \
  --workflow .github/workflows/deploy.yml \
  --mcp-config .mcp.json \
  --scenario github-actions-oidc-deploy \
  --json simulation.json \
  --markdown simulation.md
```

`simulate` accepts supplied static evidence only: a proposed command string, a GitHub
Actions workflow snapshot, MCP config JSON, MCPAudit JSON, Claude subagent frontmatter,
Codex/Claude hook-policy snapshot, and built-in static scenario fixtures. It does not read
credentials, launch MCP servers, contact network endpoints, dispatch workflows, deploy, or
run destructive probes. The JSON and Markdown outputs summarize `read`, `write`, `send`,
`deploy`, `bypass`, and `escalate` capabilities, confidence, deterministic evidence,
live-probe-needed gaps, and the active safety boundary.

List built-in static scenarios:

```bash
agent-permission-diff simulate --list-scenarios
```

Current scenario fixtures:

- `command-approval-laundering`
- `github-actions-oidc-deploy`
- `mcp-broad-tool-schema-drift`
- `claude-subagent-inherited-bypass`
- `hook-policy-bypass-gap`

Gate modes:

- `observe`: records whether the threshold was met but always exits 0.
- `warn`: exits 2 when findings meet `--fail-on`; intended for soft rollout checks.
- `enforce`: exits 2 when findings meet `--fail-on`; intended for required checks.

Default gate threshold is `critical`.

JSON and Markdown reports include the evaluated gate decision: mode, `fail_on`,
whether the threshold was met, status, exit code, and reason. The composite Action also
exposes `gate-status` and `gate-threshold-met` outputs for workflow wiring.

Acknowledgement policy:

```yaml
acknowledgements:
  - rule_id: APD001
    paths:
      - .github/workflows/agent-runner.yml
    reason: Self-hosted runner is protected by repository-only triggers and runner groups.
    expires: "2026-12-31"
```

Pass the file with `--policy .agent-permission-diff.yml` or the Action `policy` input.
Acknowledged findings stay visible in JSON, Markdown, SARIF, and PR comments, but are
excluded from gate decisions. Each acknowledgement must match the finding rule and all
finding paths; expired acknowledgements are ignored.

## GitHub Action

The composite action expects the repository to be checked out with enough history to
compare the base and head refs.

```yaml
permissions:
  contents: read
  security-events: write # only needed when upload-sarif is true

steps:
  - uses: actions/checkout@v7
    with:
      fetch-depth: 0

  - uses: saagpatel/agent-permission-diff-bot@v0.4.0
    with:
      mode: observe
      upload-sarif: "false"
```

To also create or update a sticky pull request comment, opt in with `comment: "true"`
and grant `issues: write` and `pull-requests: write` to the scanning job:

```yaml
permissions:
  contents: read
  issues: write # only needed when comment is true
  pull-requests: write # needed by some PR comment runs

steps:
  - uses: actions/checkout@v7
    with:
      fetch-depth: 0

  - uses: saagpatel/agent-permission-diff-bot@v0.4.0
    with:
      mode: observe
      comment: "true"
      upload-sarif: "false"
```

The action preserves the scanner exit code if PR commenting fails, and emits a workflow
warning instead of masking the permission-diff result.

## Action Inputs

| Input | Required | Default | Description |
|---|---|---|---|
| `base-ref` | No | `""` | Base Git ref or SHA. Defaults to the pull request base SHA when available. |
| `head-ref` | No | `""` | Head Git ref or SHA. Defaults to the pull request head SHA or current SHA. |
| `mode` | No | `observe` | Gate mode: `observe`, `warn`, or `enforce`. |
| `fail-on` | No | `critical` | Minimum severity that exits 2 in `warn`/`enforce` mode. |
| `policy` | No | `""` | Optional YAML policy file containing acknowledgement entries. |
| `json` | No | `agent-permission-diff.json` | JSON report output path. Empty string disables JSON output. |
| `sarif` | No | `agent-permission-diff.sarif` | SARIF 2.1.0 output path. Empty string disables SARIF output. |
| `markdown` | No | `""` | Markdown report output path. Empty string disables Markdown artifact output. |
| `step-summary` | No | `"true"` | Append the Markdown report to the GitHub Actions step summary. |
| `comment` | No | `"false"` | Create or update a sticky pull request comment with the Markdown report. Requires `issues: write` and may require `pull-requests: write`. |
| `upload-sarif` | No | `"false"` | Upload SARIF to GitHub code scanning. Requires `security-events: write`. |
| `working-directory` | No | `"."` | Repository working-directory to scan. |

## Action Outputs

| Output | Description |
|---|---|
| `json-file` | Path to the JSON report. |
| `sarif-file` | Path to the SARIF report. |
| `markdown-file` | Path to the Markdown report. |
| `exit-code` | `agent-permission-diff` exit code. |
| `max-severity` | Maximum finding severity from the JSON report. |
| `findings-count` | Number of findings from the JSON report. |
| `gate-status` | Gate decision status: `observe`, `pass`, `warn`, or `fail`. |
| `gate-threshold-met` | Whether the maximum finding severity met the `fail-on` threshold. |
