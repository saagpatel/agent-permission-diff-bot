.PHONY: setup check build

setup:
	@command -v uv >/dev/null || { echo "uv is required; install uv 0.13.0 and rerun make setup." >&2; exit 127; }
	uv sync --locked

check:
	@command -v uv >/dev/null || { echo "uv is required; install uv 0.13.0 and rerun make setup." >&2; exit 127; }
	uv lock --check
	uv run ruff format --check .
	uv run ruff check .
	uv run mypy src
	uv run pytest

build:
	@command -v uv >/dev/null || { echo "uv is required; install uv 0.13.0 and rerun make setup." >&2; exit 127; }
	uv build
	wheel=$$(python3 -c 'from pathlib import Path; print(max(Path("dist").glob("agent_permission_diff_bot-*-py3-none-any.whl"), key=lambda path: path.stat().st_mtime_ns))') && \
	uv run --isolated --with "$$wheel" agent-permission-diff --help
