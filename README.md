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
- MCP Registry metadata and server cards: identity, versions, packages, remotes,
  transports, authentication declarations, capabilities, compatibility, and endpoints.
- GitHub Actions: token permissions, OIDC, runner labels, trigger context, environments,
  secrets/env references, and deploy/publish actions.
- Egress policy: `allow_hosts`, `allow_connectors`, `network_name_globs`, and related
  policy keys.
- Agent instructions: `AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, Copilot instructions, Cursor rules, and
  Windsurf rules.
- Claude settings: lifecycle hooks, permission rules/modes, project MCP opt-ins, env keys,
  statusLine and credential/header helpers, plugins, and marketplaces (including committed local
  settings).
- VS Code tasks/settings and `*.code-workspace` tasks: case-insensitive `folderOpen` automatic
  tasks and terminal execution settings.
- Codex project config/hooks and profiles: lifecycle commands, sandbox/approval modes, and MCP
  servers, including `*.config.toml` profile files under `.codex/`.
- Gemini settings and Cursor hooks: lifecycle commands and Gemini MCP servers;
  Cursor `.mdc` rules with `alwaysApply: true` and hidden Unicode are flagged.
- Startup payloads: suspicious command/credential signals and literal repo-relative hook/task
  files; analysis is static only. Startup config paths match case-insensitively, including
  nested project directories.

`APD105` (unreleased) reports critical worm-shaped persistence when an auto-start trigger (`SessionStart`,
VS Code `folderOpen`, Claude `statusLine`, or a Claude credential helper) newly references an
existing executable, its referenced executable is newly added, or an existing referenced
executable is modified and the new content carries a payload smell. Git-ref scans read startup
configs at both refs even when the configs are unchanged, so a payload introduced or swapped in a
later PR is still correlated. A smell-free edit to an existing auto-start script under an
unchanged trigger is reported as HIGH `APD012`, so routine setup-script maintenance does not fail
the default critical gate. A newly introduced Claude hook and VS Code `folderOpen` pairing is also critical,
including when one side already exists. This static pattern does not establish infection.
Other hook events (`PreToolUse`, `PostToolUse`, `Stop`, `UserPromptSubmit`, etc.) referencing a
new or modified executable produce HIGH `APD012`, without critical `APD105` unless paired with
`folderOpen`. Adding a formatter hook alone therefore does not fail the default critical gate.

Target resolution handles literal command/args paths, known project-root variables, common
interpreter options, and clear shell wrappers including `env`, `sudo`, `cd` command chains, and
shell stdin scripts. VS Code `windows`/`osx`/`linux` overrides and bounded `dependsOn` task chains
are analyzed as possible startup paths. Unique case-only target matches are correlated; collisions
remain unresolved. Dynamic shell expansion remains unresolved and is reported as HIGH `APD015`
when source snapshots change; complete identical base/head snapshots remain quiet. Directory and
Git readers also compare a private bounded source-state census so payload-only changes to otherwise
uninteresting files can keep opaque startup commands visible. The census excludes credentials and
vendor trees, considers at most 50,000 paths and 64 MiB of directory file content (2 MiB per file),
and never publishes its digests. Oversized, unreadable, raced, or unsafe non-vendor entries leave
coverage incomplete; unresolved startup commands may therefore retain `APD015` even when the
visible file snapshots are identical. This is a conservative coverage warning, not evidence that
an excluded file was read or that an opaque command executed.
Explicit targets can be read from vendor directories, but `.git`, credential paths, external
paths and symlinks are excluded. Startup configs accept a leading BOM and JSONC comments and
trailing commas. Unparseable configs produce HIGH findings; a raw `folderOpen` marker in an
unparseable task config also preserves the automatic-task finding. Parsing is cached per
snapshot; startup configs are limited to 32 MiB, and larger ones produce CRITICAL
`APD013` findings. A raw `folderOpen` marker is searched across the full accepted config. Other
inputs remain limited to 2 MiB, and inline executable-load analysis is capped at 64 KiB. Hidden
Unicode is checked across all supported instruction files. Payload smells
in config files are checked on command strings rather than unrelated settings keys or values.

## Installation

**Python >= 3.11 required.**

Pin a source install to an immutable commit. The SHA below is the task's base revision; replace it
with the full SHA for the revision you reviewed. Unreleased features are available only after that
revision includes them:

```bash
pip install "git+https://github.com/saagpatel/agent-permission-diff-bot.git@d778c6f711d6b77399ef29430a0e06b067c0c7f5"
```

## Usage

Compare two Git refs:

```bash
agent-permission-diff diff --repo . --base-ref origin/main --head-ref HEAD
```

Compare two relative directories:

```bash
agent-permission-diff diff --base-dir base --head-dir head --markdown report.md
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

Compare two declared MCP server metadata snapshots without network or credentials:

```bash
agent-permission-diff server-card-diff \
  --base-file snapshots/v1/server.json \
  --head-file snapshots/v2/server.json \
  --json server-card-drift.json \
  --markdown server-card-drift.md \
  --sarif server-card-drift.sarif
```

The unreleased examiner also accepts directories or local Git refs, distinguishes `ABSENT` from
`UNKNOWN`, preserves Registry/protocol/vendor provenance, and never treats declared
metadata as observed runtime behavior. Use `server-card-diff --explain-schema` or
`--json-schema report` for the versioned contract. See
[MCP Server Card Drift Examiner](docs/server-card-drift.md) and the
[CI recipe](docs/server-card-ci-recipe.md).

Run a static no-credential, no-network permission simulation before executing a command or
workflow:

```bash
agent-permission-diff simulate \
  --command 'gh pr create --repo saagpatel/example' \
  --workflow .github/workflows/deploy.yml \
  --mcp-config .mcp.json \
  --scenario github-actions-oidc-deploy \
  --json simulation.json \
  --json-summary simulation-summary.json \
  --markdown simulation.md
```

By default, `simulate` accepts supplied static evidence only: a proposed command string, a GitHub
Actions workflow snapshot, MCP config JSON, MCPAudit JSON, Claude subagent frontmatter,
Codex/Claude hook-policy snapshot, and built-in static scenario fixtures. Unless the explicit
live GitHub Actions probe is requested, it does not read credentials or contact network endpoints.
It never launches MCP servers, dispatches workflows, deploys, or runs destructive probes. The
JSON and Markdown outputs summarize `read`, `write`, `send`,
`deploy`, `bypass`, and `escalate` capabilities, confidence, deterministic evidence,
live-probe-needed gaps, structured `risk_facets`, and the active safety boundary.

`risk_facets` records analyzer-emitted machine-readable categories such as
`token_inheritance`, `deployment_gate`, `artifact_exposure`,
`reusable_workflow_boundary`, `secret_exposure`, and `pull_request_target_boundary`.
Each facet includes a status, confidence, and indexes back to deterministic evidence,
live probe evidence, and live-probe-needed gaps.

Use `--json-summary` when automation only needs compact capability levels, risk facet
statuses/counts, inputs, and live-probe-needed gaps without the full evidence payload.
See [Simulation Output Contract](docs/simulation-output.md) for downstream automation
examples.

Use `simulate --explain-schema` when automation needs machine-readable simulator contract
metadata before running a simulation. It prints schema versions, capability names, risk
facets, input kinds, built-in scenarios, supported probes, and live-probe boundaries without
reading input files or running probes.

Use `simulate --json-schema summary`, `simulate --json-schema full`, or
`simulate --json-schema contract` when integrations need a JSON Schema for validating
simulator artifacts. Schema export is also static and exits before reading input files or
running probes.

Use `simulate --validate-json PATH --schema summary|full|contract` to validate an existing
simulation artifact offline against the exported schemas. The command prints JSON with
`valid` and `errors`, exits `0` for valid artifacts, and exits `2` for validation failures.
See [Simulation CI Recipe](docs/simulation-ci-recipe.md) for a static GitHub Actions
pattern that generates, validates, and routes a simulation summary.

For supplied GitHub Actions workflow snapshots, `simulate` also flags
`pull_request_target` workflows that check out or execute pull request head code, since
that can collapse fork isolation into privileged token or secret exposure. Obvious
non-fork guards such as `github.event.pull_request.head.repo.fork == false` are recorded
as mitigating evidence while still requiring guard review.

The simulator records explicit and inherited `GITHUB_TOKEN` permission posture. Workflows
or jobs that omit `permissions` are reported as inherited live defaults, with follow-up
gaps for repository or organization default token settings. Broad `permissions: write-all`
and jobs that inherit write-capable workflow permissions are called out separately.

Reusable workflow and action trust boundaries are also classified. Static reports call out
local reusable workflows, external reusable workflows, `secrets: inherit`, local composite
actions, and action references that are not pinned to full commit SHAs. These are reported
as deterministic trust-boundary evidence with live-probe-needed gaps for called workflow
code, caller secrets, local action contents, and floating ref trust.

Deployment gates are treated as another static boundary. Deploy-shaped jobs, OIDC publish
paths, missing job `environment` gates, visible deployment environments, and supplied
branch/tag trigger filters are classified, with live-probe-needed gaps for required
reviewers, wait timers, protected environment secrets, and branch/tag deployment rules.

The workflow simulator also classifies common GitHub Actions data-exposure paths such as
artifact uploads, cache save/restore steps, GitHub secret references, and writes to
`GITHUB_OUTPUT`, `GITHUB_ENV`, or `GITHUB_STEP_SUMMARY`. These are static signals only:
the report separates deterministic evidence from live-probe-needed checks for artifact
retention, visibility, cache isolation, masking, and trigger-specific secret availability.

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

List live-read-only probe adapters:

```bash
agent-permission-diff simulate --list-probes
```

Probe adapters are off by default and must be explicitly requested. The first adapter is
`github-actions-readonly`, which consumes a supplied GitHub Actions metadata JSON snapshot
and separates the result into `live_probe_evidence`. It does not call GitHub, read
credentials, dispatch workflows, mutate checks, or deploy:

```bash
agent-permission-diff simulate \
  --probe github-actions-readonly \
  --github-actions-probe-json checks.json \
  --json simulation.json
```

If `--probe github-actions-readonly` is supplied without
`--github-actions-probe-json`, the simulator records a live-probe-needed gap instead of
performing a lookup.

An explicit credential-aware read-only mode can fetch GitHub Actions metadata from
`api.github.com` when all live context is supplied:

```bash
agent-permission-diff simulate \
  --probe github-actions-readonly \
  --github-actions-live \
  --github-repository saagpatel/agent-permission-diff-bot \
  --github-ref HEAD_SHA_OR_BRANCH \
  --github-token-env GITHUB_TOKEN \
  --json simulation.json
```

Live GitHub probing is off unless `--github-actions-live` is present. The live adapter
only sends GET requests to `api.github.com`, requires `--github-repository` and
`--github-ref`, caps request timeouts at 30 seconds, and reports the token source as an
environment variable name such as `env:GITHUB_TOKEN` without including the token value.
It does not dispatch workflows, read repository secrets, mutate checks, create comments,
deploy, or contact arbitrary hosts. If `--github-pull-number` is supplied without
`--github-ref`, the simulator first performs one additional GET request to resolve the PR
head SHA and records that resolution as live probe evidence. When GitHub returns head and
base repository metadata, the simulator also records whether the PR is cross-repository
and flags fork/base trust review as a live-probe-needed gap.

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

## Allow-rule reach explanations (experimental)

Config Guard explains what a new allow rule really reaches (for example, that `Bash(git *)`
also allows `git -c alias.x='!cmd' x`) with a vendored copy of the Range allow-rule engine and
its cited knowledge base (`src/agent_permission_diff_bot/_vendor/therange/`). That engine was
written for a user's own, trusted config; here it reads files from pull requests, so its output
is **experimental**. Treat "what this now allows" as a lower bound. Known limits, tracked in
[#56](https://github.com/saagpatel/agent-permission-diff-bot/issues/56):

- An option between subcommand words, such as `Bash(gh release -R owner/repo *)` or
  `Bash(git submodule --quiet *)`, can hide reach the engine would otherwise report. An
  option right after the program (`Bash(git -C . *)`) is handled: it is rated as the bare
  program.
- Codex `.rules` files are read for plain `prefix_rule(...)` calls only. Aliased calls,
  `**` keyword unpacking, tuple patterns and unknown decisions are skipped, not refused.
- A few unusual literals (a very long hex integer) can fail as an error rather than an
  unreadable-file finding, and an empty union element drops its rule.

What does fail closed: a program the knowledge base does not know is reported as high
("unknown reach"), never as safe; a rules file whose patterns expand past 256 commands or
2,000 rules, or that cannot be parsed, is reported as unreadable; and aliased or oversized
skill frontmatter is reported as unreadable.

## Agent Config Guard and Swallowed checks (experimental)

The pull request checks in `agent_permission_diff_bot.checks` (part of the unreleased GitHub
App) are **experimental**. Known gaps, tracked in
[#60](https://github.com/saagpatel/agent-permission-diff-bot/issues/60):

- Skill frontmatter is loaded with YAML merge-key aliases resolved, so a small hostile file
  can expand before the size checks run. Until analysis runs inside `run_limited`, treat a
  check that does not finish as a failure (Config Guard already concludes `failure`).
- Skip-check instructions are found in added lines; a weakening edited into one line of a
  hard-wrapped sentence, or two instructions in one line where the first is negated, can
  be missed.
- Swallowed does not yet report flag assignments inside promise `.catch()` handlers.
- Known false positives: invalid-YAML skill frontmatter with no tools line, unreadable
  rule files the PR did not touch, and a subagent's `tools:` restriction read as an allow
  rule. `@mentions` in quoted PR text are not escaped.

## Analysis containment (experimental)

`agent_permission_diff_bot.limited.run_limited` runs a function in a freshly spawned child
process under one deadline, a memory cap (`RLIMIT_AS`, enforced on Linux only) and a
bounded JSON result (8 MiB, 200 levels deep by default), so hostile pull request input can
exhaust only the child. It is **experimental** and not yet wired into the GitHub App.
Known limits, tracked in the follow-up issue linked from its pull request:

- The deadline is only as strong as Python threads allow: argument encoding and the
  child's start-up run in a helper thread, and work that cannot be interrupted there can
  keep the caller waiting until the shutdown grace period ends.
- On macOS and Windows there is no enforced memory cap; only the deadline bounds the child.
- Results come back as plain JSON data; callers convert them to their own types.

## GitHub App (unreleased, experimental)

`agent-permission-diff app serve` runs a GitHub App with two check runs and one pull request
comment, updated in place on every push:

- **Agent Config Guard** explains what a PR now lets an agent do: new allow rules expanded
  into what they really reach (using the vendored Range knowledge base), removed deny rules,
  wider permission modes, new hooks and MCP servers, skill `allowed-tools`, Codex `.rules`, and
  new instruction lines telling agents to skip a check. Each finding has a suggested fix.
- **Swallowed errors** finds new places where the diff catches an error and drops it, in
  Python and TypeScript/JavaScript, ranked by what they could hide: auth, data loss, network.

The App reads files through the API and never runs pull request code. It needs the `app`
extra (`pip install "agent-permission-diff-bot[app]"`). Registration steps, settings, and a
local replay that proves the whole flow without network access are in
[docs/github-app.md](docs/github-app.md).

The App is **experimental**. Known limits, tracked in
[#62](https://github.com/saagpatel/agent-permission-diff-bot/issues/62): its analysis does
not yet run inside `run_limited`, so pathological input is bounded by snapshot limits rather
than a memory cap; pull requests with more than 300 changed files always fail Config Guard;
and queued events live in the server process, so a restart drops them (re-run the check).

## GitHub Action

The composite action expects the repository to be checked out with enough history to
compare the base and head refs.

```yaml
permissions:
  contents: read
  security-events: write # only needed when upload-sarif is true

steps:
  - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
    with:
      fetch-depth: 0

  - uses: saagpatel/agent-permission-diff-bot@d778c6f711d6b77399ef29430a0e06b067c0c7f5
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
  - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
    with:
      fetch-depth: 0

  - uses: saagpatel/agent-permission-diff-bot@d778c6f711d6b77399ef29430a0e06b067c0c7f5
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
| `working-directory` | No | `"."` | Repository working directory to scan. |

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

## Status

### Stack

- Python 3.11 and newer; Python 3.14.8 is the pinned local development interpreter.
- uv 0.13.0, Ruff, mypy, and pytest are pinned through `pyproject.toml` and `uv.lock`.

### Known risks

- Simulator inputs and reports are static unless the explicit GitHub Actions live probe is
  requested. A live probe reads GitHub metadata and cannot prove repository policy, required
  reviewers, secret availability, or deployment behavior.
- Server-card reports compare declared metadata and do not establish runtime behavior.
- CI covers Python 3.11 through 3.14; setup-python does not yet provide Python 3.15.
- Features listed under `Unreleased` in [CHANGELOG.md](CHANGELOG.md) are not part of a
  published release.

### Next steps

- Run `make setup`, `make check`, and `make build` before proposing changes.
- Review generated JSON, SARIF, and Markdown when changing analyzer behavior or output
  contracts.
