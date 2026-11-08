"""Build the checks' inputs from the GitHub API, mirroring the local Git snapshot reader.

Config Guard gets base and head snapshots of the agent-facing files: changed files it
reads, every startup config (context for correlating hooks with their scripts), and the
scripts those configs reference. Swallowed gets the head text and added lines of each
changed Python or TypeScript file. Credential paths are never fetched, and blob sizes
are checked from the tree before anything is downloaded.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Any, Protocol

from agent_permission_diff_bot.checks.config_guard import is_guard_path
from agent_permission_diff_bot.checks.swallowed import (
    PYTHON_SUFFIXES,
    TS_SUFFIXES,
    ChangedFile,
    added_lines_from_patch,
)
from agent_permission_diff_bot.persistence import (
    ConfigCache,
    is_sensitive_path,
    project_config_kind,
    snapshot_hook_references,
)
from agent_permission_diff_bot.sources import (
    MAX_CONFIG_INPUT_BYTES,
    MAX_INPUT_BYTES,
    MAX_SOURCE_STATE_FILES,
    SOURCE_STATE_COVERAGE_KEY,
    SOURCE_STATE_DIGEST_KEY,
    _is_vendor_path,
    _mark_incomplete,
    _too_large_reason,
)

MAX_GUARD_FILES = 300
MAX_SWALLOWED_FILES = 200


class TreeReader(Protocol):
    def tree(self, sha: str) -> tuple[dict[str, dict[str, Any]], bool]: ...

    def blob_text(self, sha: str) -> str: ...


@dataclass
class PullInputs:
    base_files: dict[str, str]
    head_files: dict[str, str]
    swallowed_files: list[ChangedFile]
    guard_notes: list[str] = field(default_factory=list)
    swallowed_notes: list[str] = field(default_factory=list)


def collect_inputs(
    repo: TreeReader, base_sha: str, head_sha: str, pull_files: list[dict[str, Any]]
) -> PullInputs:
    notes: list[str] = []
    swallowed_notes: list[str] = []
    changed = [str(f["filename"]) for f in pull_files]
    previous = [str(f["previous_filename"]) for f in pull_files if f.get("previous_filename")]
    if len(pull_files) >= 3000:
        notes.append("GitHub lists at most 3,000 changed files; later files were not read.")
        swallowed_notes.append(notes[-1])
    base_tree, base_truncated = repo.tree(base_sha)
    head_tree, head_truncated = repo.tree(head_sha)
    if base_truncated or head_truncated:
        notes.append(
            "GitHub truncated a repository tree; unchanged startup configs may be missing."
        )
    base_files = _snapshot(repo, base_tree, [*changed, *previous], base_truncated, notes)
    head_files = _snapshot(repo, head_tree, changed, head_truncated, notes)
    return PullInputs(
        base_files=base_files,
        head_files=head_files,
        swallowed_files=_swallowed_files(repo, pull_files, swallowed_notes),
        guard_notes=notes,
        swallowed_notes=swallowed_notes,
    )


def _snapshot(
    repo: TreeReader,
    tree: dict[str, dict[str, Any]],
    changed: Iterable[str],
    truncated: bool,
    notes: list[str],
) -> dict[str, str]:
    wanted = {path for path in changed if is_guard_path(path)}
    wanted.update(path for path in tree if project_config_kind(path) is not None)
    selected = sorted(
        path
        for path in wanted
        if path in tree and not is_sensitive_path(path) and not _is_vendor_path(path)
    )
    if len(selected) > MAX_GUARD_FILES:
        notes.append(f"Only the first {MAX_GUARD_FILES} agent-facing files were read.")
        selected = selected[:MAX_GUARD_FILES]
    files: dict[str, str] = {}
    for path in selected:
        limit = MAX_CONFIG_INPUT_BYTES if project_config_kind(path) else MAX_INPUT_BYTES
        _read(repo, tree, path, limit, files)
    cache: ConfigCache = {}
    for path in sorted(snapshot_hook_references(files, cache, tree.keys())):
        if path in files or is_sensitive_path(path):
            continue
        if ".git" in {part.casefold() for part in path.split("/")}:
            continue
        if path in tree:
            _read(repo, tree, path, MAX_INPUT_BYTES, files)
        else:
            _mark_incomplete(files, path, "referenced input is absent from the selected Git tree")
    _source_state(files, tree, changed, truncated)
    return files


def _read(
    repo: TreeReader, tree: dict[str, dict[str, Any]], path: str, limit: int, files: dict[str, str]
) -> None:
    entry = tree[path]
    if int(entry.get("size") or 0) > limit:
        _mark_incomplete(files, path, _too_large_reason(limit))
        return
    if str(entry.get("mode", "")) in {"120000", "160000"}:
        _mark_incomplete(files, path, "input is a symlink or submodule in the selected Git tree")
        return
    files[path] = repo.blob_text(str(entry["sha"]))


def _source_state(
    files: dict[str, str],
    tree: dict[str, dict[str, Any]],
    changed: Iterable[str],
    truncated: bool,
) -> None:
    """The same private digest the local Git reader computes, from tree entries."""
    selected = sorted({p for p in changed if not is_sensitive_path(p) and not _is_vendor_path(p)})
    incomplete = truncated or len(selected) > MAX_SOURCE_STATE_FILES
    entries = []
    for path in selected[:MAX_SOURCE_STATE_FILES]:
        path_hash = hashlib.sha256(path.encode("utf-8", errors="surrogateescape")).hexdigest()
        entry = tree.get(path)
        mode, object_id = (
            (str(entry.get("mode")), str(entry.get("sha"))) if entry else ("missing", "missing")
        )
        entries.append(f"{path_hash}:{mode}:{object_id}")
    files[SOURCE_STATE_DIGEST_KEY] = hashlib.sha256("\n".join(entries).encode()).hexdigest()
    files[SOURCE_STATE_COVERAGE_KEY] = "incomplete" if incomplete else "complete"


def _swallowed_files(
    repo: TreeReader, pull_files: list[dict[str, Any]], notes: list[str]
) -> list[ChangedFile]:
    out: list[ChangedFile] = []
    skipped_patch = 0
    for item in pull_files:
        path = str(item["filename"])
        if item.get("status") == "removed" or is_sensitive_path(path) or _is_vendor_path(path):
            continue
        if PurePosixPath(path).suffix.lower() not in (*PYTHON_SUFFIXES, *TS_SUFFIXES):
            continue
        patch = item.get("patch")
        if not patch:
            skipped_patch += 1
            continue
        added = added_lines_from_patch(str(patch))
        if not added:
            continue
        if len(out) >= MAX_SWALLOWED_FILES:
            notes.append(f"Only the first {MAX_SWALLOWED_FILES} changed source files were scanned.")
            break
        out.append(ChangedFile(path=path, text=repo.blob_text(str(item["sha"])), added=added))
    if skipped_patch:
        notes.append(
            f"{skipped_patch} source file(s) had no patch from GitHub (too large) "
            "and were not scanned."
        )
    return out
