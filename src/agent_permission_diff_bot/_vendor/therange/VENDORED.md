# Vendored: the Range allow-rule expansion engine

Source: the Range project, commit `347055c96079fa8b3604dde797a8c2084857dc62`
(`src/therange/`). The upstream repository is local-only, so it is vendored
rather than installed.

Copied unchanged: `model.py`, `claude_rules.py`.

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
- `codex_rules.py`: every parse failure of an untrusted file (`TypeError` from an
  unhashable literal, `RecursionError`, `ValueError` for a NUL byte on Python 3.11) is raised
  as `RulesParseError`, so callers refuse the file instead of crashing.
- `engine.py`: a rule with an option anywhere in its fixed words (`Bash(git -C . *)`,
  `Bash(gh release -R o/r *)`) is rated as the words before that option, since other
  options and any later subcommand can follow it; and a Codex suggestion is rated as the
  prefix rule it is emitted as, not as an exact command.
- `codex_rules.py`: only plain top-level `prefix_rule(...)` calls with literal arguments
  are read; any other statement, an aliased call, unpacked arguments, an unknown keyword or
  decision, or a pattern element that is not a string or a non-empty list of strings refuses
  the whole file, so a pull request cannot hide an allow rule from the parser.
- `knowledge/commands.toml`: `fd --exec` is its own capability. It no longer shares
  `find`'s Claude Code safeguard, which does not cover fd.
- Trailing blank lines at end of file are removed so `git diff --check` stays clean.

Formatting and lint are excluded for this directory so a re-sync stays a plain
copy. To re-sync, copy the files above from upstream and reapply every local patch listed above (the `codex_rules.py` limits are the security-relevant ones).
