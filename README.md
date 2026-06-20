# Agent Permission Diff Bot

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

Gate modes:

- `observe`: always exits 0.
- `warn`: exits 2 only when findings meet `--fail-on`.
- `enforce`: same gate behavior as `warn`, intended for stricter policy files later.

Default gate threshold is `critical`.

## GitHub Action

The composite action expects the repository to be checked out with enough history to
compare the base and head refs.

```yaml
permissions:
  contents: read
  security-events: write # only needed when upload-sarif is true

steps:
  - uses: actions/checkout@v6
    with:
      fetch-depth: 0

  - uses: ./agent-permission-diff-bot
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
  - uses: actions/checkout@v6
    with:
      fetch-depth: 0

  - uses: saagpatel/agent-permission-diff-bot@v0.2.1
    with:
      mode: observe
      comment: "true"
      upload-sarif: "false"
```

The action preserves the scanner exit code if PR commenting fails, and emits a workflow
warning instead of masking the permission-diff result.
