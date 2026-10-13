from __future__ import annotations

import hashlib
import subprocess
from collections.abc import Iterable
from pathlib import Path

from agent_permission_diff_bot.persistence import (
    ConfigCache,
    project_config_kind,
    snapshot_hook_references,
)
from agent_permission_diff_bot.surfaces import is_interesting_path

MAX_INPUT_BYTES = 2 * 1024 * 1024
INCOMPLETE_PREFIX = ".agent-permission-diff-incomplete/"


class InputTooLargeError(ValueError):
    pass


def read_dir_snapshot(
    root: Path,
    referenced: Iterable[str] = (),
    config_cache: ConfigCache | None = None,
) -> tuple[str, dict[str, str]]:
    root = root.resolve()
    if not root.is_dir():
        raise FileNotFoundError(
            f"scan root does not exist or is not a directory: {root.name or '.'}"
        )
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
            content = _read_bounded(path)
            if content is None:
                _mark_incomplete(files, rel, "input exceeds 2 MiB")
            else:
                files[rel] = content
        except OSError:
            _mark_incomplete(files, rel, "input is unreadable")
    explicit_references = set(referenced)
    references = snapshot_hook_references(files, config_cache) | explicit_references
    for rel in sorted(references):
        if rel not in files and ".git" not in {part.lower() for part in rel.split("/")}:
            reference_path = available.get(rel) or _safe_reference(root, rel)
            if reference_path is not None:
                try:
                    content = _read_bounded(reference_path)
                    if content is None:
                        _mark_incomplete(files, rel, "referenced input exceeds 2 MiB")
                    else:
                        files[rel] = content
                except OSError:
                    _mark_incomplete(files, rel, "referenced input is unreadable")
            else:
                _mark_incomplete(files, rel, "referenced input is absent")
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
        if path not in tree_paths:
            continue
        try:
            content = _git_show(repo, ref, path)
        except InputTooLargeError:
            _mark_incomplete(files, path, "input exceeds 2 MiB")
            continue
        if content is not None:
            files[path] = content
        else:
            _mark_incomplete(files, path, "input is unreadable in the selected Git tree")
    references = snapshot_hook_references(files, config_cache) | set(referenced)
    for path in sorted(references):
        if path not in files and ".git" not in {part.lower() for part in path.split("/")}:
            try:
                content = _git_show(repo, ref, path)
            except InputTooLargeError:
                _mark_incomplete(files, path, "referenced input exceeds 2 MiB")
                continue
            if content is not None:
                files[path] = content
            else:
                reason = "referenced input is absent from the selected Git tree"
                if path in tree_paths:
                    reason = "referenced input is unreadable in the selected Git tree"
                _mark_incomplete(files, path, reason)
    return ref, files


def changed_git_paths(repo: Path, base_ref: str, head_ref: str) -> list[str]:
    output = _run_git(repo, ["diff", "--name-only", f"{base_ref}..{head_ref}"])
    return [line.strip() for line in output.splitlines() if line.strip()]


def _git_files(repo: Path, ref: str) -> list[str]:
    output = _run_git(repo, ["ls-tree", "-r", "--name-only", ref])
    return [line.strip() for line in output.splitlines() if line.strip()]


def _git_show(repo: Path, ref: str, path: str) -> str | None:
    process = subprocess.Popen(
        ["git", "-C", str(repo), "show", f"{ref}:{path}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    if process.stdout is None:
        process.kill()
        process.wait()
        return None
    content = process.stdout.read(MAX_INPUT_BYTES + 1)
    if len(content) > MAX_INPUT_BYTES:
        process.kill()
        process.stdout.close()
        process.wait()
        raise InputTooLargeError("input exceeds 2 MiB")
    if process.wait() != 0:
        return None
    return content.decode("utf-8", errors="surrogateescape")


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


def _read_bounded(path: Path) -> str | None:
    with path.open("rb") as stream:
        content = stream.read(MAX_INPUT_BYTES + 1)
    if len(content) > MAX_INPUT_BYTES:
        return None
    return content.decode("utf-8", errors="surrogateescape")


def _mark_incomplete(files: dict[str, str], path: str, reason: str) -> None:
    key = INCOMPLETE_PREFIX + hashlib.sha256(path.encode()).hexdigest()
    files[key] = f"{path}: {reason}"
