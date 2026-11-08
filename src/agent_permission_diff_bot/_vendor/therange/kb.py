"""Load the curated command knowledge base."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from functools import lru_cache
from importlib import resources
from typing import Literal

Position = Literal["after", "before-subcommand", "subcommand"]
Kind = Literal["flag", "any"]
ExactMode = Literal["applies", "script-file"]


@dataclass(frozen=True)
class Capability:
    id: str
    paths: tuple[tuple[str, ...], ...]
    position: Position
    kind: Kind
    triggers: tuple[str, ...]
    effect: str
    severity: str
    title: str
    explain: str
    example: str
    narrower: str
    doc: str
    exact: ExactMode = "applies"
    claude_mitigated: str = ""
    demo: str = ""
    implicit_after: tuple[str, ...] = ()
    builtins: frozenset[str] = frozenset()


@dataclass(frozen=True)
class Interpose:
    program: str
    flag: str
    doc: str
    verified: str
    after_words: int = 1
    only: tuple[str, ...] = ()


@dataclass
class KnowledgeBase:
    capabilities: list[Capability]
    pins: dict[str, list[str]]
    interpose: dict[str, Interpose] = field(default_factory=dict)

    def programs(self) -> set[str]:
        return {path[0] for cap in self.capabilities for path in cap.paths}


def parse_kb(data: dict[str, object]) -> KnowledgeBase:
    caps: list[Capability] = []
    raw_caps = data.get("capability", [])
    assert isinstance(raw_caps, list)
    for entry in raw_caps:
        assert isinstance(entry, dict)
        missing = [k for k in ("id", "paths", "kind", "effect", "severity", "title", "explain", "doc") if k not in entry]
        if missing:
            raise ValueError(f"knowledge base entry {entry.get('id', '?')} is missing {missing}")
        caps.append(
            Capability(
                id=entry["id"],
                paths=tuple(tuple(p) for p in entry["paths"]),
                position=entry.get("position", "after"),
                kind=entry["kind"],
                triggers=tuple(entry.get("triggers", ())),
                effect=entry["effect"],
                severity=entry["severity"],
                title=entry["title"],
                explain=entry["explain"],
                example=entry.get("example", ""),
                narrower=entry.get("narrower", ""),
                doc=entry["doc"],
                exact=entry.get("exact", "applies"),
                claude_mitigated=entry.get("claude_mitigated", ""),
                demo=entry.get("demo", ""),
                implicit_after=tuple(entry.get("implicit_after", ())),
                builtins=frozenset(entry.get("builtins", ())),
            )
        )
    pins_raw = data.get("pins", {})
    assert isinstance(pins_raw, dict)
    interpose: dict[str, Interpose] = {}
    raw_interpose = data.get("interpose", {})
    assert isinstance(raw_interpose, dict)
    for program, entry in raw_interpose.items():
        assert isinstance(entry, dict)
        interpose[program] = Interpose(
            program=program,
            flag=entry["flag"],
            doc=entry["doc"],
            verified=entry.get("verified", ""),
            after_words=int(entry.get("after_words", 1)),
            only=tuple(entry.get("only", ())),
        )
    return KnowledgeBase(capabilities=caps, pins={k: list(v) for k, v in pins_raw.items()}, interpose=interpose)


@lru_cache(maxsize=1)
def load_kb() -> KnowledgeBase:
    text = resources.files(__package__ or "agent_permission_diff_bot._vendor.therange").joinpath("knowledge/commands.toml").read_text(encoding="utf-8")
    return parse_kb(tomllib.loads(text))
