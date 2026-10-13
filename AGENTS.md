# Purpose

Agent Permission Diff Bot detects and explains changes to agent-facing permissions. Keep the
default scan and simulator static, with no credentials and no network access. The optional
GitHub Actions probe is read-only and must be explicitly requested.

# Layout

- `src/agent_permission_diff_bot/`: CLI, diff engine, surfaces, simulator, and server-card examiner.
- `tests/`: regression tests and static fixtures.
- `docs/`: output contracts, recipes, and server-card behavior.
- `schemas/`: checked-in JSON schemas.

# Setup

Use Python 3.14.8 and uv 0.13.0. Run `make setup` to install the locked development environment.

# Checks

Run `make check` for lock, formatting, lint, type, and test checks. Run `make build` for package
build and installed-wheel smoke verification.

Cursor Cloud should use `make setup` and `make check`.

# Boundaries

Simulation uses supplied evidence only unless the explicit live GitHub Actions probe is requested.
It never launches MCP servers, executes analyzed commands, dispatches workflows, deploys, or runs
destructive probes. Keep credential values out of all report formats. Preserve the distinction
between static evidence, live probe evidence, and live-probe-needed gaps.

## Review guidelines

Focus Codex review on permission-diff correctness, exact JSON/SARIF/Markdown output contracts,
simulator gate exit codes, acknowledgement handling, pull_request_target and fork/base trust
boundaries, OIDC/deployment gates, GITHUB_TOKEN permission inheritance, reusable workflow
boundaries, artifact and cache exposure, and static-vs-live probe separation. Treat changes that
perform network or credential reads without explicit flags, hide live-probe gaps, misclassify
write/deploy/bypass capabilities, or make unsafe workflows look acknowledged or low-risk as
merge-relevant.

For docs-only PRs, comment only when docs claim a simulator boundary, schema, gate behavior, probe
behavior, or CI recipe that the reviewed code, fixtures, or contract docs do not support.

# Delivery

Keep changes scoped, preserve unrelated work, and include regression tests for behavior changes.
Before delivery, run `make check`, `make build`, and `git diff --check`. Do not claim hosted CI,
provider state, or deployment behavior from local checks.
