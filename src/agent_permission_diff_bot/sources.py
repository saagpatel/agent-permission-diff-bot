from __future__ import annotations

import subprocess
from collections.abc import Iterable
from pathlib import Path

from agent_permission_diff_bot.persistence import (
    ConfigCache,
    project_config_kind,
    snapshot_hook_references,
)
from agent_permission_diff_bot.surfaces import is_interesting_path


def read_dir_snapshot(
    root: Path,
    referenced: Iterable[str] = (),
    config_cache: ConfigCache | None = None,
) -> tuple[str, dict[str, str]]:
    root = root.resolve()
    files: dict[str, str] = {}
    available: dict[str, Path] = {}
    for path in root.rglob("*"):
        if not path.is_file() or path.is_symlink() or not path.resolve().is_relative_to(root):
            continue
        rel = path.relative_to(root).as_posix()
        if _is_vendor_path(rel) or ".git" in {part.lower() for part in rel.split("/")}:
            continue
        available[rel] = path
        if project_config_kind(rel) is None and not is_interesting_path(rel):
            continue
        try:
            files[rel] = path.read_bytes().decode("utf-8", errors="surrogateescape")
        except OSError:
            continue
    explicit_references = set(referenced)
    references = snapshot_hook_references(files, config_cache) | explicit_references
    for rel in sorted(references):
        if rel not in files and ".git" not in {part.lower() for part in rel.split("/")}:
            reference_path = available.get(rel) or _safe_reference(root, rel)
            if reference_path is not None:
                try:
                    files[rel] = reference_path.read_bytes().decode(
                        "utf-8", errors="surrogateescape"
                    )
                except OSError:
                    continue
    return str(root), files


def read_git_snapshot(
    repo: Path,
    ref: str,
    paths: Iterable[str] | None = None,
    referenced: Iterable[str] = (),
    config_cache: ConfigCache | None = None,
) -> tuple[str, dict[str, str]]:
    tree_paths = _git_files(repo, ref)
    interesting = set(tree_paths if paths is None else paths)
    # In repo mode startup configuration is snapshot context even when unchanged in
    # this diff. It is needed to correlate a changed payload with its existing trigger.
    interesting.update(path for path in tree_paths if project_config_kind(path) is not None)
    files: dict[str, str] = {}
    for path in sorted(interesting):
        if _is_vendor_path(path) or (
            project_config_kind(path) is None and not is_interesting_path(path)
        ):
            continue
        content = _git_show(repo, ref, path)
        if content is not None:
            files[path] = content
    references = snapshot_hook_references(files, config_cache) | set(referenced)
    for path in sorted(references):
        if path not in files and ".git" not in {part.lower() for part in path.split("/")}:
            content = _git_show(repo, ref, path)
            if content is not None:
                files[path] = content
    return ref, files


def changed_git_paths(repo: Path, base_ref: str, head_ref: str) -> list[str]:
    output = _run_git(repo, ["diff", "--name-only", f"{base_ref}..{head_ref}"])
    return [line.strip() for line in output.splitlines() if line.strip()]


def _git_files(repo: Path, ref: str) -> list[str]:
    output = _run_git(repo, ["ls-tree", "-r", "--name-only", ref])
    return [line.strip() for line in output.splitlines() if line.strip()]


def _git_show(repo: Path, ref: str, path: str) -> str | None:
    result = subprocess.run(
        ["git", "-C", str(repo), "show", f"{ref}:{path}"],
        check=False,
        capture_output=True,
    )
    if result.returncode != 0:
        return None
    if isinstance(result.stdout, str):
        # Keep compatibility with simple subprocess fakes; production subprocess
        # calls return bytes so newline sequences and invalid UTF-8 survive intact.
        return result.stdout
    return result.stdout.decode("utf-8", errors="surrogateescape")


def _run_git(repo: Path, args: list[str]) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout


def _is_vendor_path(path: str) -> bool:
    parts = {part.lower() for part in path.split("/")}
    return bool(parts & {"node_modules", ".venv", "venv", ".git", "vendor", "pods", ".build"})


def _safe_reference(root: Path, rel: str) -> Path | None:
    """Resolve a literal repository reference without following symlinks."""
    candidate_rel = Path(rel)
    if candidate_rel.is_absolute() or any(part in {"", ".", ".."} for part in rel.split("/")):
        return None
    if ".git" in {part.lower() for part in candidate_rel.parts}:
        return None
    candidate = root / candidate_rel
    try:
        if not candidate.resolve().is_relative_to(root):
            return None
        current = root
        for part in candidate_rel.parts:
            current = current / part
            if current.is_symlink():
                return None
        return candidate if candidate.is_file() else None
    except OSError:
        return None
