# Changelog

## 0.5.0

- Added `agent-permission-diff simulate` for static/no-credential/no-network permission
  simulation across commands, GitHub Actions workflows, MCP config/MCPAudit evidence,
  Claude subagents, hook-policy snapshots, and built-in scenario fixtures.
- Added structured simulator outputs: full JSON, compact JSON summary, Markdown, risk
  facets, live-probe-needed gaps, schema discovery, JSON Schema export, and offline JSON
  validation.
- Added static scenario fixtures for approval laundering, OIDC deploy escalation, broad MCP
  tool/schema drift, Claude subagent inherited/bypass permissions, and hook-policy bypass
  gaps.
- Added explicit live-read-only GitHub Actions probe plumbing with live probes disabled by
  default.
- Added simulator output docs, docs-contract tests, a CI recipe, and repo-local agent
  context.

## 0.4.0

- Baseline release documented by existing README install and action examples.
