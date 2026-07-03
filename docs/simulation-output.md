# Simulation Output Contract

`agent-permission-diff simulate` has two JSON output shapes for downstream automation:

- `--json` writes the full simulation report, including capability evidence, deterministic evidence, live probe evidence, live-probe-needed gaps, and `risk_facets` with indexes back into those evidence arrays.
- `--json-summary` writes a compact automation contract with capability levels, risk facet statuses/counts, inputs, and live-probe-needed gaps, while omitting the full evidence arrays.

Both modes are static/no-credential/no-network unless an explicit live read-only probe flag is supplied.

## Full JSON

Use `--json` when a consumer needs traceability back to exact evidence strings.

The examples below use this workflow snapshot:

```yaml
name: Publish
on:
  workflow_dispatch:
permissions:
  id-token: write
jobs:
  publish:
    uses: org/platform/.github/workflows/release.yml@main
    secrets: inherit
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: pypa/gh-action-pypi-publish@release/v1
```

```bash
agent-permission-diff simulate \
  --workflow workflow.yml \
  --json simulation.json
```

Excerpt:

```json
{
  "schema_version": "agent-permission-simulation.v1",
  "mode": "static/no-credential/no-network",
  "capabilities": {
    "deploy": {
      "confidence": "medium",
      "evidence": [
        "deploy/publish step: pypa/gh-action-pypi-publish@release/v1",
        "Job `deploy` contains deploy/publish-shaped steps."
      ],
      "level": "yes"
    },
    "send": {
      "confidence": "medium",
      "evidence": [
        "deploy/publish step: pypa/gh-action-pypi-publish@release/v1",
        "Workflow calls external reusable workflow code outside this repository."
      ],
      "level": "possible"
    }
  },
  "risk_facets": {
    "deployment_gate": {
      "confidence": "medium",
      "deterministic_evidence_indices": [
        11
      ],
      "live_probe_evidence_indices": [],
      "live_probe_needed_indices": [
        7,
        8,
        9
      ],
      "status": "review_needed"
    },
    "reusable_workflow_boundary": {
      "confidence": "medium",
      "deterministic_evidence_indices": [
        4,
        6,
        7,
        8,
        10
      ],
      "live_probe_evidence_indices": [],
      "live_probe_needed_indices": [
        3,
        4,
        6
      ],
      "status": "review_needed"
    },
    "secret_exposure": {
      "confidence": "medium",
      "deterministic_evidence_indices": [
        5,
        9
      ],
      "live_probe_evidence_indices": [],
      "live_probe_needed_indices": [
        5
      ],
      "status": "review_needed"
    },
    "token_inheritance": {
      "confidence": "medium",
      "deterministic_evidence_indices": [],
      "live_probe_evidence_indices": [],
      "live_probe_needed_indices": [
        1,
        2
      ],
      "status": "review_needed"
    }
  },
  "live_probe_needed": [
    "OIDC provider trust policy and GitHub environment protections require live/API review.",
    "Confirm job `publish` needs inherited write-capable GITHUB_TOKEN permissions.",
    "Confirm job `deploy` needs inherited write-capable GITHUB_TOKEN permissions.",
    "External reusable workflow `org/platform/.github/workflows/release.yml@main` is not pinned to a full SHA."
  ]
}
```

## Summary JSON

Use `--json-summary` when automation needs a stable, compact decision surface without carrying the full evidence payload.

```bash
agent-permission-diff simulate \
  --workflow workflow.yml \
  --json-summary simulation-summary.json
```

Example:

```json
{
  "capabilities": {
    "bypass": {
      "confidence": "medium",
      "level": "possible"
    },
    "deploy": {
      "confidence": "medium",
      "level": "yes"
    },
    "escalate": {
      "confidence": "high",
      "level": "yes"
    },
    "read": {
      "confidence": "medium",
      "level": "possible"
    },
    "send": {
      "confidence": "medium",
      "level": "possible"
    },
    "write": {
      "confidence": "high",
      "level": "yes"
    }
  },
  "input_count": 1,
  "inputs": [
    {
      "kind": "workflow",
      "notes": [],
      "source": "snapshot",
      "status": "parsed"
    }
  ],
  "live_probe_needed": [
    "OIDC provider trust policy and GitHub environment protections require live/API review.",
    "Confirm job `publish` needs inherited write-capable GITHUB_TOKEN permissions.",
    "Confirm job `deploy` needs inherited write-capable GITHUB_TOKEN permissions.",
    "External reusable workflow `org/platform/.github/workflows/release.yml@main` is not pinned to a full SHA.",
    "Confirm external reusable workflow `org/platform/.github/workflows/release.yml@main` trust, requested permissions, and called workflow code at the referenced ref.",
    "Review which caller secrets are exposed to reusable workflow job `publish`.",
    "Pin action `pypa/gh-action-pypi-publish@release/v1` to a full commit SHA or confirm trusted floating ref.",
    "Deploy-shaped job `deploy` has no visible GitHub environment gate.",
    "OIDC deploy path lacks a visible GitHub environment; confirm cloud trust policy and repository environment protections.",
    "Deploy-shaped workflow lacks visible branch or tag restrictions in supplied YAML."
  ],
  "mode": "static/no-credential/no-network",
  "risk_facets": {
    "deployment_gate": {
      "confidence": "medium",
      "evidence_count": 1,
      "live_probe_needed_count": 3,
      "status": "review_needed"
    },
    "reusable_workflow_boundary": {
      "confidence": "medium",
      "evidence_count": 5,
      "live_probe_needed_count": 3,
      "status": "review_needed"
    },
    "secret_exposure": {
      "confidence": "medium",
      "evidence_count": 2,
      "live_probe_needed_count": 1,
      "status": "review_needed"
    },
    "token_inheritance": {
      "confidence": "medium",
      "evidence_count": 0,
      "live_probe_needed_count": 2,
      "status": "review_needed"
    }
  },
  "safety_boundary": "Static simulation only: no credentials read, no network calls, no MCP server launches, no workflow dispatches, no deploys, and no destructive probes.",
  "schema_version": "agent-permission-simulation.v1.summary.v1"
}
```

## Field Notes

- `capabilities` reports each capability level and confidence without evidence text in summary mode.
- `risk_facets` reports analyzer-emitted categories. Each facet has `status`, `confidence`, `evidence_count`, and `live_probe_needed_count` in summary mode.
- `live_probe_needed` is retained in summary mode so automation can route required follow-up checks.
- Full JSON keeps `deterministic_evidence`, `live_probe_evidence`, and `live_probe_needed`, plus risk facet indexes back into those arrays.
