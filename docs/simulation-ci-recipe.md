# Simulation CI Recipe

Use this recipe when a workflow needs to generate a static simulator summary, validate the
artifact, and route follow-up work from machine-readable fields.

The default path is static/no-credential/no-network. It does not read secrets, contact
GitHub APIs, dispatch workflows, deploy, or run live probes.

## GitHub Actions

```yaml
name: Agent Permission Simulation

on:
  pull_request:
    paths:
      - ".github/workflows/**"
      - ".mcp*.json"
      - "**/AGENTS.md"
      - "**/CLAUDE.md"
  workflow_dispatch:

permissions:
  contents: read

jobs:
  simulate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Install agent-permission-diff
        run: |
          python -m pip install --upgrade pip
          python -m pip install .

      - name: Generate simulation summary
        run: |
          agent-permission-diff simulate \
            --workflow .github/workflows/deploy.yml \
            --json-summary simulation-summary.json

      - name: Validate simulation summary
        run: |
          agent-permission-diff simulate \
            --validate-json simulation-summary.json \
            --schema summary

      - name: Route simulation result
        run: |
          python - <<'PY'
          import json
          import sys

          summary = json.load(open("simulation-summary.json", encoding="utf-8"))
          risky = [
              name
              for name, data in summary["capabilities"].items()
              if data["level"] in {"yes", "possible"}
          ]
          review_needed = [
              name
              for name, data in summary["risk_facets"].items()
              if data["status"] == "review_needed"
          ]

          print("capabilities:", ", ".join(risky) or "none")
          print("risk_facets:", ", ".join(review_needed) or "none")
          if summary["live_probe_needed"]:
              print("live_probe_needed:")
              for gap in summary["live_probe_needed"]:
                  print(f"- {gap}")

          if review_needed:
              sys.exit(2)
          PY
```

## Notes

- Keep the workflow `permissions` block narrow. `contents: read` is enough for static
  simulation of checked-in snapshots.
- Run `--validate-json` before routing decisions so automation fails on malformed or stale
  summary artifacts.
- Use summary `capabilities` for coarse routing and `risk_facets` for targeted review
  queues.
- Treat `live_probe_needed` as follow-up work, not as permission to run live probes. Live
  probes require explicit probe flags and context.
- For multiple workflow files, run one simulation per file or build a wrapper that writes
  separate summaries before aggregating decisions.
