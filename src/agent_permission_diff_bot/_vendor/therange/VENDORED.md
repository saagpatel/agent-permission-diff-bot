# Vendored: the Range allow-rule expansion engine

Source: the Range project, commit `347055c96079fa8b3604dde797a8c2084857dc62`
(`src/therange/`). The upstream repository is local-only, so it is vendored
rather than installed.

Copied unchanged: `model.py`, `claude_rules.py`, `engine.py`,
`knowledge/commands.toml`.

Local patches:

- `kb.py`: the knowledge base loads from this package (`__package__`) instead of
  the top-level `therange` package.
- `sources.py`: replaced by the two documentation constants `engine.py`
  imports. Upstream `sources.py` reads local agent configuration and is not
  vendored.
- `codex_rules.py`: `expand_pattern` refuses a pattern that expands to more than 256
  commands, and `parse_rules_text` refuses more than 2,000 rules per file, by raising
  `RulesParseError`. Rules files arrive from pull requests, so an exponential union must
  fail closed instead of exhausting memory.
- Trailing blank lines at end of file are removed so `git diff --check` stays clean.

Formatting and lint are excluded for this directory so a re-sync stays a plain
copy. To re-sync, copy the files above from upstream and reapply the two patches.
