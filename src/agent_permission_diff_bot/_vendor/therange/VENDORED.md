# Vendored: the Range allow-rule expansion engine

Source: the Range project, commit `347055c96079fa8b3604dde797a8c2084857dc62`
(`src/therange/`). The upstream repository is local-only, so it is vendored
rather than installed.

Copied unchanged: `model.py`, `claude_rules.py`, `codex_rules.py`, `engine.py`,
`knowledge/commands.toml`.

Local patches:

- `kb.py`: the knowledge base loads from this package (`__package__`) instead of
  the top-level `therange` package.
- `sources.py`: replaced by the two documentation constants `engine.py`
  imports. Upstream `sources.py` reads local agent configuration and is not
  vendored.

Formatting and lint are excluded for this directory so a re-sync stays a plain
copy. To re-sync, copy the files above from upstream and reapply the two patches.
