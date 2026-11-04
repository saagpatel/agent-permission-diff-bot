from __future__ import annotations

import hashlib
import os
import stat
import subprocess
from collections.abc import Iterable
from pathlib import Path

from agent_permission_diff_bot.persistence import (
    ConfigCache,
    is_sensitive_path,
    project_config_kind,
    resolve_case_insensitive_path,
    snapshot_hook_references,
)
from agent_permission_diff_bot.surfaces import is_interesting_path

MAX_INPUT_BYTES = 2 * 1024 * 1024
MAX_CONFIG_INPUT_BYTES = 32 * 1024 * 1024
MAX_SOURCE_STATE_BYTES = 64 * 1024 * 1024
MAX_SOURCE_STATE_FILES = 50_000
INCOMPLETE_PREFIX = ".agent-permission-diff-incomplete/"
SOURCE_STATE_PREFIX = ".agent-permission-diff-source-state/"
SOURCE_STATE_DIGEST_KEY = SOURCE_STATE_PREFIX + "digest"
SOURCE_STATE_COVERAGE_KEY = SOURCE_STATE_PREFIX + "coverage"


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
    state_paths: list[tuple[str, Path]] = []
    state_overflow = False
    for path in root.rglob("*"):
        rel = path.relative_to(root).as_posix()
        if is_sensitive_path(rel):
            continue
        try:
            metadata = path.stat(follow_symlinks=False)
        except OSError:
            if _is_vendor_path(rel):
                continue
            state_overflow = True
            continue
        if _is_vendor_path(rel) and not stat.S_ISREG(metadata.st_mode):
            continue
        if stat.S_ISLNK(metadata.st_mode):
            state_overflow = True
            continue
        if stat.S_ISDIR(metadata.st_mode):
            continue
        if not stat.S_ISREG(metadata.st_mode):
            state_overflow = True
            continue
        try:
            if not path.resolve().is_relative_to(root):
                state_overflow = True
                continue
        except OSError:
            state_overflow = True
            continue
        available[rel] = path
        if _is_vendor_path(rel):
            continue
        if len(state_paths) < MAX_SOURCE_STATE_FILES:
            state_paths.append((rel, path))
        else:
            state_overflow = True
        if project_config_kind(rel) is None and not is_interesting_path(rel):
            continue
        try:
            limit = MAX_CONFIG_INPUT_BYTES if project_config_kind(rel) else MAX_INPUT_BYTES
            content = _read_bounded(
                path, limit, expected_identity=(metadata.st_dev, metadata.st_ino)
            )
            if content is None:
                _mark_incomplete(files, rel, _too_large_reason(limit))
            else:
                files[rel] = content
        except OSError:
            _mark_incomplete(files, rel, "input is unreadable")
    explicit_references = set(referenced)
    references = (
        snapshot_hook_references(files, config_cache, available.keys()) | explicit_references
    )
    for rel in sorted(references):
        if (
            rel not in files
            and not is_sensitive_path(rel)
            and ".git" not in {part.casefold() for part in rel.split("/")}
        ):
            actual_rel = resolve_case_insensitive_path(rel, available)
            reference_path = available.get(actual_rel) if actual_rel is not None else None
            reference_path = reference_path or _safe_reference(root, rel)
            snapshot_rel = actual_rel or rel
            if reference_path is not None:
                try:
                    content = _read_bounded(reference_path, MAX_INPUT_BYTES)
                    if content is None:
                        _mark_incomplete(files, snapshot_rel, "referenced input exceeds 2 MiB")
                    else:
                        files[snapshot_rel] = content
                except OSError:
                    _mark_incomplete(files, snapshot_rel, "referenced input is unreadable")
            else:
                _mark_incomplete(files, snapshot_rel, "referenced input is absent")
    _append_directory_source_state(files, state_paths, overflow=state_overflow)
    return str(root), files


def read_git_snapshot(
    repo: Path,
    ref: str,
    paths: Iterable[str] | None = None,
    referenced: Iterable[str] = (),
    config_cache: ConfigCache | None = None,
) -> tuple[str, dict[str, str]]:
    if paths is not None:
        paths = tuple(paths)
    tree_paths = _git_files(repo, ref)
    interesting = set(tree_paths if paths is None else paths)
    # In repo mode startup configuration is snapshot context even when unchanged in
    # this diff. It is needed to correlate a changed payload with its existing trigger.
    interesting.update(path for path in tree_paths if project_config_kind(path) is not None)
    files: dict[str, str] = {}
    for path in sorted(interesting):
        if (
            is_sensitive_path(path)
            or _is_vendor_path(path)
            or (project_config_kind(path) is None and not is_interesting_path(path))
        ):
            continue
        if path not in tree_paths:
            continue
        try:
            limit = MAX_CONFIG_INPUT_BYTES if project_config_kind(path) else MAX_INPUT_BYTES
            content = _git_show(repo, ref, path, limit)
        except InputTooLargeError:
            _mark_incomplete(files, path, _too_large_reason(limit))
            continue
        if content is not None:
            files[path] = content
        else:
            _mark_incomplete(files, path, "input is unreadable in the selected Git tree")
    references = snapshot_hook_references(files, config_cache, tree_paths) | set(referenced)
    for path in sorted(references):
        if (
            path not in files
            and not is_sensitive_path(path)
            and ".git" not in {part.casefold() for part in path.split("/")}
        ):
            try:
                content = _git_show(repo, ref, path, MAX_INPUT_BYTES)
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
    _append_git_source_state(files, repo, ref, paths, tree_paths)
    return ref, files


def changed_git_paths(repo: Path, base_ref: str, head_ref: str) -> list[str]:
    output = _run_git(repo, ["diff", "--name-only", f"{base_ref}..{head_ref}"])
    return [line.strip() for line in output.splitlines() if line.strip()]


def _git_files(repo: Path, ref: str) -> list[str]:
    output = _run_git(repo, ["ls-tree", "-r", "--name-only", ref])
    return [line.strip() for line in output.splitlines() if line.strip()]


def _git_show(repo: Path, ref: str, path: str, max_bytes: int = MAX_INPUT_BYTES) -> str | None:
    process = subprocess.Popen(
        ["git", "-C", str(repo), "show", f"{ref}:{path}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    if process.stdout is None:
        process.kill()
        process.wait()
        return None
    content = process.stdout.read(max_bytes + 1)
    if len(content) > max_bytes:
        process.kill()
        process.stdout.close()
        process.wait()
        raise InputTooLargeError(_too_large_reason(max_bytes))
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
    if is_sensitive_path(rel) or ".git" in {part.casefold() for part in candidate_rel.parts}:
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


def _open_regular_nofollow(path: Path, *, expected_identity: tuple[int, int] | None = None) -> int:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise OSError("input is not a regular file")
        if (
            expected_identity is not None
            and (metadata.st_dev, metadata.st_ino) != expected_identity
        ):
            raise OSError("input changed during bounded scan")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _read_bounded(
    path: Path,
    max_bytes: int = MAX_INPUT_BYTES,
    *,
    expected_identity: tuple[int, int] | None = None,
) -> str | None:
    descriptor = _open_regular_nofollow(path, expected_identity=expected_identity)
    with os.fdopen(descriptor, "rb") as stream:
        content = stream.read(max_bytes + 1)
    if len(content) > max_bytes:
        return None
    return content.decode("utf-8", errors="surrogateescape")


def _mark_incomplete(files: dict[str, str], path: str, reason: str) -> None:
    key = INCOMPLETE_PREFIX + hashlib.sha256(path.encode()).hexdigest()
    files[key] = f"{path}: {reason}"


def _too_large_reason(limit: int) -> str:
    return "input exceeds 32 MiB" if limit == MAX_CONFIG_INPUT_BYTES else "input exceeds 2 MiB"


def _append_directory_source_state(
    files: dict[str, str], paths: list[tuple[str, Path]], *, overflow: bool = False
) -> None:
    incomplete = overflow or len(paths) > MAX_SOURCE_STATE_FILES
    entries: list[str] = []
    consumed = 0
    for rel, path in sorted(paths)[:MAX_SOURCE_STATE_FILES]:
        path_hash = hashlib.sha256(rel.encode("utf-8", errors="surrogateescape")).hexdigest()
        try:
            metadata = path.stat(follow_symlinks=False)
            if not stat.S_ISREG(metadata.st_mode):
                incomplete = True
                entries.append(f"{path_hash}:non-regular")
                continue
            size = metadata.st_size
            mode = stat.S_IMODE(metadata.st_mode)
            digest: str | None = None
            if size <= MAX_INPUT_BYTES and consumed + size <= MAX_SOURCE_STATE_BYTES:
                if rel in files:
                    content = files[rel].encode("utf-8", errors="surrogateescape")
                else:
                    descriptor = _open_regular_nofollow(
                        path, expected_identity=(metadata.st_dev, metadata.st_ino)
                    )
                    with os.fdopen(descriptor, "rb") as stream:
                        content = stream.read(MAX_INPUT_BYTES + 1)
                if len(content) <= MAX_INPUT_BYTES:
                    digest = hashlib.sha256(content).hexdigest()
                    consumed += size
                else:
                    incomplete = True
            else:
                incomplete = True
            after = path.stat(follow_symlinks=False)
            if (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
                stat.S_IMODE(after.st_mode),
            ) != (
                metadata.st_dev,
                metadata.st_ino,
                metadata.st_size,
                metadata.st_mtime_ns,
                mode,
            ):
                incomplete = True
                digest = None
            if digest is not None:
                entries.append(f"{path_hash}:{size}:{mode}:content:{digest}")
            else:
                entries.append(f"{path_hash}:{size}:{metadata.st_mtime_ns}:{mode}:metadata-only")
        except OSError:
            incomplete = True
            entries.append(f"{path_hash}:unreadable")
    files[SOURCE_STATE_DIGEST_KEY] = hashlib.sha256("\n".join(entries).encode()).hexdigest()
    files[SOURCE_STATE_COVERAGE_KEY] = "incomplete" if incomplete else "complete"


def _append_git_source_state(
    files: dict[str, str],
    repo: Path,
    ref: str,
    paths: Iterable[str] | None,
    tree_paths: list[str],
) -> None:
    selected = sorted(
        {
            path
            for path in (tree_paths if paths is None else paths)
            if not is_sensitive_path(path) and not _is_vendor_path(path)
        }
    )
    incomplete = len(selected) > MAX_SOURCE_STATE_FILES
    selected = selected[:MAX_SOURCE_STATE_FILES]
    present = set(tree_paths)
    queried = [path for path in selected if path in present]
    tree_entries: dict[str, tuple[str, str]] = {}
    for offset in range(0, len(queried), 256):
        batch = queried[offset : offset + 256]
        result = subprocess.run(
            [
                "git",
                "-C",
                str(repo),
                "--literal-pathspecs",
                "ls-tree",
                "-rz",
                ref,
                "--",
                *batch,
            ],
            check=True,
            capture_output=True,
        )
        for entry in result.stdout.split(b"\0"):
            if not entry:
                continue
            header, raw_path = entry.split(b"\t", 1)
            mode, _, object_id = header.decode("ascii").split(" ", 2)
            tree_entries[raw_path.decode("utf-8", errors="surrogateescape")] = (
                mode,
                object_id,
            )
    entries = []
    for path in selected:
        path_hash = hashlib.sha256(path.encode("utf-8", errors="surrogateescape")).hexdigest()
        mode, object_id = tree_entries.get(path, ("missing", "missing"))
        entries.append(f"{path_hash}:{mode}:{object_id}")
    files[SOURCE_STATE_DIGEST_KEY] = hashlib.sha256("\n".join(entries).encode()).hexdigest()
    files[SOURCE_STATE_COVERAGE_KEY] = "incomplete" if incomplete else "complete"
