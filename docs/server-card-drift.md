# MCP Server Card Drift Examiner

`agent-permission-diff server-card-diff` compares two supplied MCP server metadata
snapshots without contacting a registry, package host, authorization server, or MCP
runtime. It accepts explicit files, directories, or local Git refs and emits deterministic
plain text, JSON, Markdown, and SARIF.

## Standards baseline

Primary-source baseline as of **2026-08-11**:

- Official MCP Registry repository at commit
  [`a25f166b4b5bee06eeecb75e4f37b2a44a8aa5be`](https://github.com/modelcontextprotocol/registry/tree/a25f166b4b5bee06eeecb75e4f37b2a44a8aa5be).
  The current publisher examples use
  [`2025-12-11/server.schema.json`](https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json).
  The Registry's generated draft schema is
  [`docs/reference/server-json/draft/server.schema.json`](https://github.com/modelcontextprotocol/registry/blob/a25f166b4b5bee06eeecb75e4f37b2a44a8aa5be/docs/reference/server-json/draft/server.schema.json),
  derived from its OpenAPI contract.
- Official MCP specification repository at commit
  [`b25c0874bf0ba699a58e21ef06f659d839659de3`](https://github.com/modelcontextprotocol/modelcontextprotocol/tree/b25c0874bf0ba699a58e21ef06f659d839659de3),
  protocol revision
  [`2026-07-28`](https://modelcontextprotocol.io/specification/2026-07-28).

Standard requirements, design inferences, and local fixture behavior are separate:

1. **Registry standard.** `server.json` requires `name`, `description`, and `version`.
   It standardizes repository metadata, packages, remotes, transports, inputs, icons,
   website URL, and namespaced `_meta`. The Generic Registry API wraps a card in `server`
   and adds official lifecycle data under
   `_meta.io.modelcontextprotocol.registry/official`.
2. **Protocol standard.** MCP `2026-07-28` separately defines `server/discover`,
   `supportedVersions`, `ServerCapabilities`, and response
   `_meta.io.modelcontextprotocol/serverInfo`. HTTP authorization is discovered through
   OAuth Protected Resource Metadata and authorization-server metadata; those documents
   are not silently treated as Registry `server.json` fields.
3. **Design inference.** Drift severity, confidence, and widened/narrowed policy are this
   product's deterministic review policy. They are not normative MCP conformance rules.
4. **Vendor and fixture data.** Fields such as top-level `authentication`,
   `securitySchemes`, `capabilities`, `compatibility`, or `endpoints` in a Registry-style
   card retain their original extension paths and `standard: false`. Synthetic fixtures
   exercise those shapes without asserting ecosystem standardization.

The Registry is still described by its own docs as preview. This examiner pins the
baseline above in every JSON report rather than assuming the contract cannot drift.

## Internal model and claim boundary

Each normalized field carries:

- source kind, label, relative path, Git ref when applicable, and content SHA-256;
- source contract family and exact original field path;
- `present`, `absent`, or `unknown` state;
- whether the field is standard under the pinned contract;
- confidence, a comparison fingerprint, and a secret-safe display value.

A missing optional field in a recognized, parseable contract is `absent`. A missing field
on a malformed card or a card declaring an unrecognized schema is `unknown`. Unknown
extension values are compared by structural fingerprint and are not printed. Values in
secret-shaped fields are always rendered as `[REDACTED]`.

Every report carries this ceiling:

> Declared metadata comparison only. No network, credential, registry, server, or runtime
> observation was performed; observed runtime behavior remains UNKNOWN.

## Drift semantics

| Kind | Meaning |
|---|---|
| `added` | A field or card is newly declared. |
| `removed` | A previously declared field or card is absent in the head. |
| `widened` | A set-valued declaration is a strict superset. |
| `narrowed` | A set-valued declaration is a strict subset. |
| `changed` | Present scalar or non-subset set values differ. |
| `unknown` | One side cannot support an absence or value claim. |

Deterministic high-signal policy includes:

- breaking compatibility, removed transports/packages/capabilities, repository identity,
  and package provenance changes: generally `high`;
- removing a required authentication declaration: `high`;
- changing a secret marker from true to false: `critical`;
- new remote endpoints: `high`; new transports or package choices: generally `medium`;
- compatibility or capability expansion: `medium`; narrowing/removal: `high`;
- ambiguous or invalid metadata: `medium` with `low` confidence.

Gate modes match the existing CLI: `observe` records and exits 0, while `warn` and
`enforce` exit 2 when a change meets `--fail-on`.

## Inputs and outputs

Compare explicit files:

```bash
agent-permission-diff server-card-diff \
  --base-file release-1/server.json \
  --head-file release-2/server.json
```

Compare discovered cards in directories:

```bash
agent-permission-diff server-card-diff \
  --base-dir snapshots/base \
  --head-dir snapshots/head \
  --json drift.json \
  --markdown drift.md \
  --sarif drift.sarif
```

Compare local Git objects without fetching:

```bash
agent-permission-diff server-card-diff \
  --repo . \
  --base-ref origin/main \
  --head-ref HEAD \
  --card-path server.json \
  --mode enforce \
  --fail-on high
```

Schema discovery and validation are static and read no snapshot files:

```bash
agent-permission-diff server-card-diff --explain-schema
agent-permission-diff server-card-diff --json-schema report
agent-permission-diff server-card-diff \
  --validate-json drift.json \
  --schema report
```

The checked-in report schema is
[`schemas/mcp-server-card-drift-report-v1.schema.json`](../schemas/mcp-server-card-drift-report-v1.schema.json).

## Five-minute local demo

From the repository root:

```bash
demo_dir="$(mktemp -d)"

uv run agent-permission-diff server-card-diff \
  --base-file tests/fixtures/server_card/current-base.server.json \
  --head-file tests/fixtures/server_card/current-head.server.json \
  --human "$demo_dir/drift.txt" \
  --json "$demo_dir/drift.json" \
  --markdown "$demo_dir/drift.md" \
  --sarif "$demo_dir/drift.sarif" \
  --mode observe \
  --fail-on high

uv run agent-permission-diff server-card-diff \
  --validate-json "$demo_dir/drift.json" \
  --schema report
```

Expected result: the first command exits 0 in observe mode and records identity, version,
package, transport, authentication, capability, endpoint, and extension drift. Validation
prints `"valid": true`. The fixture token strings do not appear in any output.

See [the CI recipe](server-card-ci-recipe.md) for a no-credential pipeline pattern.
