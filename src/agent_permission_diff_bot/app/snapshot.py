"""Build the checks' inputs from the GitHub API, mirroring the local Git snapshot reader.

Config Guard gets base and head snapshots of the agent-facing files: changed files it
reads, every startup config (context for correlating hooks with their scripts), and the
scripts those configs reference. Swallowed gets the head text and changed lines of each
changed Python or TypeScript file. Credential paths are never fetched; blob sizes are
checked from the tree where it lists them, and every download stops at its read cap.
"""

from __future__ import annotations

import hashlib
import logging
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Any, Protocol

from agent_permission_diff_bot.app.github import BlobTooLargeError
from agent_permission_diff_bot.app.limits import AnalysisLimits
from agent_permission_diff_bot.checks.config_guard import is_guard_path
from agent_permission_diff_bot.checks.swallowed import (
    MAX_FILE_BYTES,
    PYTHON_SUFFIXES,
    TS_SUFFIXES,
    ChangedFile,
    changed_lines_from_patch,
)
from agent_permission_diff_bot.limited import ChildStartError, LimitExceededError, run_limited
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

log = logging.getLogger(__name__)

MAX_GUARD_FILES = 300
MAX_SWALLOWED_FILES = 200


class TreeReader(Protocol):
    def tree(self, sha: str) -> tuple[dict[str, dict[str, Any]], bool]:
        """Blob entries of a commit's tree by path, and whether the listing was truncated."""

    def blob_text(self, sha: str, max_bytes: int) -> str:
        """A blob's text; raises ``BlobTooLargeError`` past ``max_bytes``."""


@dataclass
class PullInputs:
    base_files: dict[str, str]
    head_files: dict[str, str]
    swallowed_files: list[ChangedFile]
    guard_notes: list[str] = field(default_factory=list)
    swallowed_notes: list[str] = field(default_factory=list)


def collect_inputs(
    repo: TreeReader,
    base_sha: str,
    head_sha: str,
    pull_files: list[dict[str, Any]],
    *,
    files_truncated: bool = False,
    limits: AnalysisLimits | None = None,
) -> PullInputs:
    """Inputs for both checks.

    ``base_sha`` is the merge base and ``pull_files`` the changed files between it and
    ``head_sha`` (from the commit comparison, so they match these exact commits).
    ``files_truncated`` says GitHub may have cut the file list short.
    """
    notes: list[str] = []
    swallowed_notes: list[str] = []
    changed = [str(f["filename"]) for f in pull_files]
    previous = [str(f["previous_filename"]) for f in pull_files if f.get("previous_filename")]
    head_blobs = {
        str(f["filename"]): str(f["sha"])
        for f in pull_files
        if f.get("status") != "removed" and f.get("sha")
    }
    base_tree, base_truncated = repo.tree(base_sha)
    head_tree, head_truncated = repo.tree(head_sha)
    if base_truncated or head_truncated:
        notes.append("GitHub truncated a repository tree; unlisted files are marked unread.")
    limits = limits or AnalysisLimits()
    base_files = _snapshot(repo, base_tree, [*changed, *previous], base_truncated, {}, limits)
    head_files = _snapshot(repo, head_tree, changed, head_truncated, head_blobs, limits)
    # A truncated tree can hide a startup config nobody changed, so it never passes.
    for files, truncated in ((base_files, base_truncated), (head_files, head_truncated)):
        if truncated:
            _mark_incomplete(files, "(git tree)", "GitHub truncated the repository tree")
    if files_truncated:
        limit_note = "GitHub lists at most 300 changed files here; later files were not read."
        notes.append(limit_note)
        swallowed_notes.append(limit_note)
        _mark_incomplete(head_files, "(pull request files)", limit_note)
    return PullInputs(
        base_files=base_files,
        head_files=head_files,
        swallowed_files=_swallowed_files(repo, pull_files, head_tree, swallowed_notes),
        guard_notes=notes,
        swallowed_notes=swallowed_notes,
    )


def _snapshot(
    repo: TreeReader,
    tree: dict[str, dict[str, Any]],
    changed: Iterable[str],
    truncated: bool,
    known_blobs: Mapping[str, str],
    limits: AnalysisLimits,
) -> dict[str, str]:
    """Startup configs first, then changed agent-facing files.

    Anything not read (over the file limit, missing from a truncated tree, too large) is
    marked incomplete, which the engine reports as a finding: an unread file never passes.
    """
    changed = list(changed)
    configs = sorted(path for path in tree if project_config_kind(path) is not None)
    guard_changed = sorted(path for path in changed if is_guard_path(path))
    ordered = [
        path
        for path in dict.fromkeys([*configs, *guard_changed])
        if not is_sensitive_path(path) and not _is_vendor_path(path)
    ]
    files: dict[str, str] = {}
    reads = 0
    for index, path in enumerate(ordered):
        if index >= MAX_GUARD_FILES:
            _mark_incomplete(files, path, f"not read: over the {MAX_GUARD_FILES}-file limit")
            continue
        entry = tree.get(path)
        if entry is None and path in known_blobs:
            entry = {"sha": known_blobs[path], "mode": "100644"}
        if entry is None:
            if truncated:
                _mark_incomplete(files, path, "not listed in a truncated Git tree")
            continue
        limit = MAX_CONFIG_INPUT_BYTES if project_config_kind(path) else MAX_INPUT_BYTES
        reads += 1
        _read(repo, entry, path, limit, files)
    for path in _hook_references(files, sorted(tree), limits):
        if path in files or is_sensitive_path(path):
            continue
        if ".git" in {part.casefold() for part in path.split("/")}:
            continue
        if path not in tree:
            _mark_incomplete(files, path, "referenced input is absent from the selected Git tree")
        elif reads >= MAX_GUARD_FILES:
            # Scripts a config refers to count against the same limit as the files
            # themselves, so one config cannot make the App read without bound.
            _mark_incomplete(files, path, f"not read: over the {MAX_GUARD_FILES}-file limit")
        else:
            reads += 1
            _read(repo, tree[path], path, MAX_INPUT_BYTES, files)
    _source_state(files, tree, changed, truncated)
    return files


def reference_targets(files: dict[str, str], available: list[str]) -> list[str]:
    """Scripts the startup configs refer to. Runs in a limited child: parsing hook
    metadata from a pull request can expand a small file into a lot of data."""
    cache: ConfigCache = {}
    return sorted(snapshot_hook_references(files, cache, available))


def _hook_references(
    files: dict[str, str], available: list[str], limits: AnalysisLimits
) -> list[str]:
    try:
        targets = run_limited(
            reference_targets,
            {path: text for path, text in files.items() if project_config_kind(path)},
            available,
            timeout_s=limits.timeout_s,
            memory_bytes=limits.memory_bytes,
        )
        if not isinstance(targets, list) or not all(isinstance(t, str) for t in targets):
            raise ValueError("unexpected reference list")
        return list(targets)
    except (LimitExceededError, ChildStartError, RuntimeError, ValueError) as exc:
        log.warning("Hook references were not resolved: %s", exc)
        _mark_incomplete(
            files, "(hook references)", "startup config references could not be resolved"
        )
        return []


def _read(
    repo: TreeReader, entry: Mapping[str, Any], path: str, limit: int, files: dict[str, str]
) -> None:
    if int(entry.get("size") or 0) > limit:
        _mark_incomplete(files, path, _too_large_reason(limit))
        return
    if str(entry.get("mode", "")) in {"120000", "160000"}:
        _mark_incomplete(files, path, "input is a symlink or submodule in the selected Git tree")
        return
    try:
        files[path] = repo.blob_text(str(entry["sha"]), limit)
    except BlobTooLargeError:
        _mark_incomplete(files, path, _too_large_reason(limit))


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
    repo: TreeReader,
    pull_files: list[dict[str, Any]],
    head_tree: Mapping[str, Mapping[str, Any]],
    notes: list[str],
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
            if item.get("status") == "renamed" and not int(item.get("changes") or 0):
                continue  # a pure rename: no line changed, so nothing new to scan
            skipped_patch += 1
            continue
        changed = changed_lines_from_patch(str(patch))
        if not changed:
            continue
        if len(out) >= MAX_SWALLOWED_FILES:
            notes.append(f"Only the first {MAX_SWALLOWED_FILES} changed source files were scanned.")
            break
        size = int((head_tree.get(path) or {}).get("size") or 0)
        if size > MAX_FILE_BYTES:
            notes.append(f"`{path}` is over 1 MiB and was not scanned.")
            continue
        try:
            # A size missing from a truncated tree is unknown, not zero: the read is capped.
            text = repo.blob_text(str(item["sha"]), MAX_FILE_BYTES)
        except BlobTooLargeError:
            notes.append(f"`{path}` is over 1 MiB and was not scanned.")
            continue
        out.append(ChangedFile(path=path, text=text, changed=changed))
    if skipped_patch:
        notes.append(
            f"{skipped_patch} source file(s) had no patch from GitHub (too large) "
            "and were not scanned."
        )
    return out
