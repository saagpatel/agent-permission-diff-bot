from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path

from agent_permission_diff_bot.server_card_model import (
    RawServerCard,
    SourceProvenance,
    SourceSnapshot,
)


class ServerCardInputError(ValueError):
    """Raised when an explicit offline snapshot cannot be read safely."""


def read_server_card_file(path: Path, *, label: str | None = None) -> SourceSnapshot:
    resolved = path.resolve()
    if not resolved.is_file():
        raise ServerCardInputError(f"server-card file does not exist: {resolved}")
    text = resolved.read_text(encoding="utf-8")
    provenance = SourceProvenance(
        kind="file",
        label=label or str(resolved),
        path=resolved.name,
        sha256=_sha256(text),
    )
    return SourceSnapshot(
        label=label or str(resolved),
        kind="file",
        cards=(RawServerCard(provenance=provenance, text=text),),
    )


def read_server_card_directory(
    root: Path,
    *,
    label: str | None = None,
    card_paths: tuple[str, ...] = (),
) -> SourceSnapshot:
    resolved = root.resolve()
    if not resolved.is_dir():
        raise ServerCardInputError(f"server-card directory does not exist: {resolved}")
    if card_paths:
        paths = [_safe_child(resolved, item) for item in card_paths]
    else:
        paths = [path for path in resolved.rglob("*.json") if _is_card_candidate(path.name)]
    cards: list[RawServerCard] = []
    for path in sorted(set(paths)):
        if not path.is_file() or _is_vendor_path(path.relative_to(resolved).as_posix()):
            continue
        text = path.read_text(encoding="utf-8")
        rel = path.relative_to(resolved).as_posix()
        cards.append(
            RawServerCard(
                provenance=SourceProvenance(
                    kind="directory",
                    label=label or str(resolved),
                    path=rel,
                    sha256=_sha256(text),
                ),
                text=text,
            )
        )
    if not cards:
        raise ServerCardInputError(
            f"no server-card JSON files found in {resolved}; use --card-path for custom names"
        )
    return SourceSnapshot(label=label or str(resolved), kind="directory", cards=tuple(cards))


def read_server_card_git_ref(
    repo: Path,
    ref: str,
    *,
    label: str | None = None,
    card_paths: tuple[str, ...] = (),
) -> SourceSnapshot:
    resolved = repo.resolve()
    if not (resolved / ".git").exists() and not _is_git_worktree(resolved):
        raise ServerCardInputError(f"not a Git repository: {resolved}")
    if not ref or ref.startswith("-") or any(character in ref for character in ("\n", "\r")):
        raise ServerCardInputError("Git ref must be a non-option, single-line ref name or SHA")
    for path in card_paths:
        _validate_git_path(path)
    _run_git(resolved, ["rev-parse", "--verify", f"{ref}^{{commit}}"])
    paths = list(card_paths) if card_paths else _git_paths(resolved, ref)
    cards: list[RawServerCard] = []
    for path in sorted(set(paths)):
        if _is_vendor_path(path) or (not card_paths and not _is_card_candidate(Path(path).name)):
            continue
        text = _git_show(resolved, ref, path)
        if text is None:
            if card_paths:
                raise ServerCardInputError(f"{ref}:{path} is not a readable file")
            continue
        cards.append(
            RawServerCard(
                provenance=SourceProvenance(
                    kind="git_ref",
                    label=label or f"{resolved}@{ref}",
                    path=path,
                    sha256=_sha256(text),
                    git_ref=ref,
                ),
                text=text,
            )
        )
    if not cards:
        raise ServerCardInputError(
            f"no server-card JSON files found at {ref}; use --card-path for custom names"
        )
    return SourceSnapshot(
        label=label or f"{resolved}@{ref}",
        kind="git_ref",
        cards=tuple(cards),
    )


def _is_card_candidate(name: str) -> bool:
    lowered = name.lower()
    return (
        lowered == "server.json" or lowered == "mcp-server.json" or lowered.endswith(".server.json")
    )


def _safe_child(root: Path, relative: str) -> Path:
    candidate = (root / relative).resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise ServerCardInputError(f"card path escapes snapshot root: {relative}") from exc
    return candidate


def _git_paths(repo: Path, ref: str) -> list[str]:
    output = _run_git(repo, ["ls-tree", "-r", "--name-only", ref])
    return [line for line in output.splitlines() if line]


def _git_show(repo: Path, ref: str, path: str) -> str | None:
    result = subprocess.run(
        ["git", "-C", str(repo), "show", f"{ref}:{path}"],
        check=False,
        capture_output=True,
        text=True,
    )
    return result.stdout if result.returncode == 0 else None


def _run_git(repo: Path, args: list[str]) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or "git command failed"
        raise ServerCardInputError(detail)
    return result.stdout


def _is_git_worktree(path: Path) -> bool:
    marker = path / ".git"
    return marker.is_file()


def _validate_git_path(path: str) -> None:
    candidate = Path(path)
    if (
        not path
        or candidate.is_absolute()
        or ".." in candidate.parts
        or any(character in path for character in ("\n", "\r", "\x00"))
    ):
        raise ServerCardInputError(f"card path must be a clean relative Git path: {path!r}")


def _is_vendor_path(path: str) -> bool:
    return bool(set(Path(path).parts) & {".git", ".venv", "venv", "vendor", "node_modules"})


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()
