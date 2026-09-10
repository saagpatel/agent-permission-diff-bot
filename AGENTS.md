## Review guidelines

Focus Codex review on permission-diff correctness, exact JSON/SARIF/Markdown
output contracts, simulator gate exit codes, acknowledgement handling,
pull_request_target and fork/base trust boundaries, OIDC/deployment gates,
`GITHUB_TOKEN` permission inheritance, reusable workflow boundaries, artifact
and cache exposure, and static-vs-live probe separation. Treat changes that
perform network or credential reads without explicit flags, hide live-probe
gaps, misclassify write/deploy/bypass capabilities, or make unsafe workflows
look acknowledged or low-risk as merge-relevant.

For docs-only PRs, comment only when docs claim a simulator boundary, schema,
gate behavior, probe behavior, or CI recipe that the reviewed code, fixtures, or
contract docs do not support.

<!-- portfolio-context:start -->
# Portfolio Context

## What This Project Is

agent-permission-diff-bot is an active local project in the ~/Projects portfolio.

## Current State

Portfolio truth currently marks this project as `active` with `boilerplate` context. Phase 104 recovered minimum-viable context so future sessions can resume without rediscovery.

## Stack

- Primary stack: Python

## How To Run

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
  --json-summary simulation-summary.json \
  --markdown simulation.md
```

`simulate` accepts supplied static evidence only: a proposed command string, a GitHub
Actions workflow snapshot, MCP config JSON, MCPAudit JSON, Claude subagent frontmatter,
Codex/Claude hook-policy snapshot, and built-in static scenario fixtures. It does not read
credentials, launch MCP servers, contact network endpoints, dispatch workflows, deploy, or
run destructive probes. The JSON and Markdown outputs summarize `read`, `write`, `send`,
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
simulator artifacts. Schema export is static and exits before reading input files or
running probes.

Use `simulate --validate-json PATH --schema summary|full|contract` to validate an existing
simulation artifact offline against the exported schemas. The command prints JSON with
`valid` and `errors`, exits `0` for valid artifacts, and exits `2` for validation failures.
See `docs/simulation-ci-recipe.md` for a static GitHub Actions pattern that generates,
validates, and routes a simulation summary.

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

## Known Risks

- This repo now has repo-local recovery context plus simulator contract docs. Deeper
  product roadmap details may still live in supporting docs or future handoff artifacts.

## Next Recommended Move

Use this context plus the README and supporting docs to resume the next active task. For
simulator integration work, start from `docs/simulation-output.md` and
`docs/simulation-ci-recipe.md`, then keep default behavior static/no-credential/no-network
unless a live probe is explicitly requested.

## Cursor Cloud specific instructions

Cursor Cloud uses `.cursor/environment.json` to install the locked development
environment on Ubuntu with Python 3.11.15. Cloud work must stay static and
fixture-driven by default: do not read credentials, contact live APIs, dispatch
workflows, or execute analyzed commands unless a task explicitly authorizes the
existing opt-in live-probe boundary.

Verify changes with:

```sh
uv run ruff format --check .
uv run ruff check .
uv run pytest
uv build
```

<!-- portfolio-context:end -->
