"""Build a local demo repository from the App's recorded test scenarios.

``main`` holds the shared base files; each scenario becomes a branch with its head files,
ready to push and open as a pull request. Everything is synthetic. The script only writes
under the target directory and never pushes:

    python3 scripts/make_demo_repo.py /path/to/new/demo-repo
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

FIXTURES = Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "app"
SCENARIOS = (
    "broad-bash-allow",
    "silent-except",
    "ts-swallowed-catch",
    "hook-mcp-instructions",
    "fewer-prompts",
    "release-helpers",
    "quiet-failures",
)


def git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)


def write_tree(repo: Path, source: Path) -> None:
    for path in sorted(source.rglob("*")):
        if path.is_file():
            target = repo / path.relative_to(source)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(path.read_bytes())
            if target.suffix == ".sh":
                target.chmod(0o755)


def main(target: str) -> int:
    repo = Path(target)
    if repo.exists() and any(repo.iterdir()):
        print(f"{repo} is not empty; pick a new directory.", file=sys.stderr)
        return 2
    repo.mkdir(parents=True, exist_ok=True)
    git(repo, "init", "-q", "-b", "main")
    write_tree(repo, FIXTURES / SCENARIOS[0] / "base")
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "chore: demo baseline")
    for name in SCENARIOS:
        event = json.loads((FIXTURES / name / "event.json").read_text(encoding="utf-8"))
        title = event["payload"]["pull_request"]["title"]
        git(repo, "switch", "-q", "-c", name, "main")
        write_tree(repo, FIXTURES / name / "head")
        git(repo, "add", "-A")
        git(repo, "commit", "-qm", title)
        print(f"{name}: {title}")
    git(repo, "switch", "-q", "main")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]) if len(sys.argv) == 2 else 2)
