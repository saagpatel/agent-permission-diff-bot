from __future__ import annotations

import subprocess
from collections.abc import Iterable
from pathlib import Path

from agent_permission_diff_bot.persistence import snapshot_hook_references
from agent_permission_diff_bot.surfaces import is_interesting_path


def read_dir_snapshot(root: Path, referenced: Iterable[str] = ()) -> tuple[str, dict[str, str]]:
    root = root.resolve()
    files: dict[str, str] = {}
    available: dict[str, Path] = {}
    for path in root.rglob("*"):
        if not path.is_file() or path.is_symlink() or not path.resolve().is_relative_to(root):
            continue
        rel = path.relative_to(root).as_posix()
        if _is_vendor_path(rel):
            continue
        available[rel] = path
        if not is_interesting_path(rel):
            continue
        try:
            files[rel] = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
    for rel in sorted(snapshot_hook_references(files) | set(referenced)):
        if rel not in files and rel in available:
            try:
                files[rel] = available[rel].read_text(encoding="utf-8")
            except UnicodeDecodeError:
                # Preserve presence for correlation even when payload bytes are not text.
                files[rel] = ""
    return str(root), files


def read_git_snapshot(
    repo: Path, ref: str, paths: Iterable[str] | None = None, referenced: Iterable[str] = ()
) -> tuple[str, dict[str, str]]:
    interesting = sorted(set(_git_files(repo, ref) if paths is None else paths))
    files: dict[str, str] = {}
    for path in interesting:
        if _is_vendor_path(path) or not is_interesting_path(path):
            continue
        content = _git_show(repo, ref, path)
        if content is not None:
            files[path] = content
    for path in sorted(snapshot_hook_references(files) | set(referenced)):
        if path not in files and not _is_vendor_path(path):
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
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if result.returncode != 0:
        return None
    return result.stdout


def _run_git(repo: Path, args: list[str]) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout


def _is_vendor_path(path: str) -> bool:
    parts = set(path.split("/"))
    return bool(parts & {"node_modules", ".venv", "venv", ".git", "vendor", "Pods", ".build"})
