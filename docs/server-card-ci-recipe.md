# MCP Server Card Drift CI Recipe

This lane is deterministic and offline by default. CI needs repository contents and local
Git history only; it does not need a registry token, MCP server, OAuth client, package-host
credential, or outbound request.

```yaml
name: MCP server card drift

on:
  pull_request:
    paths:
      - server.json
      - "**/*.server.json"

permissions:
  contents: read

jobs:
  server-card-drift:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
        with:
          fetch-depth: 0

      - uses: actions/setup-python@v6
        with:
          python-version: "3.12"

      - name: Install uv
        run: python -m pip install uv

      - name: Compare declared MCP metadata
        run: |
          uv run agent-permission-diff server-card-diff \
            --repo . \
            --base-ref "${{ github.event.pull_request.base.sha }}" \
            --head-ref "${{ github.event.pull_request.head.sha }}" \
            --card-path server.json \
            --json mcp-server-card-drift.json \
            --markdown mcp-server-card-drift.md \
            --sarif mcp-server-card-drift.sarif \
            --mode enforce \
            --fail-on high

      - name: Validate report contract
        if: always()
        run: |
          uv run agent-permission-diff server-card-diff \
            --validate-json mcp-server-card-drift.json \
            --schema report
```

If a repository has several cards, repeat `--card-path` or omit it to discover
`server.json`, `mcp-server.json`, and `*.server.json`. Artifact upload and SARIF upload are
deliberately not included because they are separate external-write and permissions
decisions. Add them only under the repository's own retention and code-scanning policy.
