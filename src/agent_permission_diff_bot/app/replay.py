"""Replay a recorded webhook through the real App against the in-memory GitHub.

The whole path runs: HMAC signature check, App JWT signed with a throwaway RSA key,
repository-scoped installation token, API reads, two check runs and the comment
upsert. No network, no real key, no real token.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import warnings
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from agent_permission_diff_bot.app.fake_github import FakeGitHub, read_git_tree, read_tree_dir
from agent_permission_diff_bot.app.server import create_app
from agent_permission_diff_bot.app.settings import AppSettings
from agent_permission_diff_bot.model import Severity

with warnings.catch_warnings():
    # Starlette's TestClient warns that its httpx backend is deprecated; it still works.
    warnings.simplefilter("ignore")
    from fastapi.testclient import TestClient

REPLAY_APP_ID = "123456"


@dataclass
class Recording:
    """A webhook (event name and payload) plus the files at the base and head commits."""

    event: str
    payload: dict[str, Any]
    base: dict[str, str]
    head: dict[str, str]

    @classmethod
    def load(cls, directory: Path) -> Recording:
        event = json.loads((directory / "event.json").read_text(encoding="utf-8"))
        return cls(
            event=str(event["event"]),
            payload=dict(event["payload"]),
            base=read_tree_dir(directory / "base"),
            head=read_tree_dir(directory / "head"),
        )

    @classmethod
    def from_git(cls, repo: Path, base_ref: str, head_ref: str, number: int = 1) -> Recording:
        fake = FakeGitHub("replay", repo.resolve().name, number, REPLAY_APP_ID, "")
        base, head = read_git_tree(repo, base_ref), read_git_tree(repo, head_ref)
        fake.set_pull(base, head)
        return cls(event="pull_request", payload=fake.pull_request_payload(), base=base, head=head)


@dataclass
class ReplayResult:
    status_code: int
    github: FakeGitHub
    responses: list[int] = field(default_factory=list)

    @property
    def comment(self) -> str:
        bodies = [c["body"] for c in self.github.comments.values() if c["performed_via_github_app"]]
        return str(bodies[-1]) if bodies else ""

    def check_runs(self) -> list[dict[str, Any]]:
        return list(self.github.check_runs.values())


class Replayer:
    """One App instance and one in-memory GitHub, so pushes can be replayed in sequence."""

    def __init__(self, recording: Recording, *, guard_fail_on: Severity | None = Severity.HIGH):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        private_pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode()
        public_pem = (
            key.public_key()
            .public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
            )
            .decode()
        )
        payload = recording.payload
        repository = payload["repository"]
        pull = payload.get("pull_request") or payload["check_run"]["pull_requests"][0]
        self.github = FakeGitHub(
            owner=str(repository["owner"]["login"]),
            name=str(repository["name"]),
            number=int(pull["number"]),
            app_id=REPLAY_APP_ID,
            public_key=public_pem,
            installation_id=int(payload["installation"]["id"]),
            repository_id=int(repository["id"]),
        )
        self.secret = secrets.token_hex(32)
        settings = AppSettings(
            app_id=REPLAY_APP_ID,
            private_key=private_pem,
            webhook_secret=self.secret,
            api_url="https://api.github.test",
            guard_fail_on=guard_fail_on,
            swallowed_fail_on=None,
        )
        self.client = TestClient(create_app(settings, transport=self.github.transport()))
        self.recording = recording

    def send(
        self,
        recording: Recording | None = None,
        *,
        signature: str | None = None,
        advance_head: bool = True,
    ) -> int:
        """Deliver a webhook. ``advance_head=False`` replays a late delivery for an older push."""
        recording = recording or self.recording
        pulls = recording.payload.get("check_run", {}).get("pull_requests") or [{}]
        pull = recording.payload.get("pull_request") or pulls[0]
        if pull.get("base") and pull.get("head"):
            self.github.commits[str(pull["base"]["sha"])] = recording.base
            self.github.commits[str(pull["head"]["sha"])] = recording.head
            self.github.base_sha = str(pull["base"]["sha"])
            if advance_head or not self.github.head_sha:
                self.github.head_sha = str(pull["head"]["sha"])
        body = json.dumps(recording.payload).encode()
        digest = hmac.new(self.secret.encode(), body, hashlib.sha256).hexdigest()
        response = self.client.post(
            "/webhook",
            content=body,
            headers={
                "X-GitHub-Event": recording.event,
                "X-GitHub-Delivery": secrets.token_hex(8),
                "X-Hub-Signature-256": signature if signature is not None else f"sha256={digest}",
                "Content-Type": "application/json",
            },
        )
        return response.status_code

    def result(self, status_code: int) -> ReplayResult:
        return ReplayResult(status_code=status_code, github=self.github)


def replay(recording: Recording) -> ReplayResult:
    replayer = Replayer(recording)
    return replayer.result(replayer.send())


def main_replay(
    directory: str | None, git_repo: str | None, base: str, head: str, comment_out: str | None
) -> int:
    if git_repo:
        recording = Recording.from_git(Path(git_repo), base, head)
    elif directory:
        recording = Recording.load(Path(directory))
    else:
        raise ValueError("pass a recording directory or --git-repo")
    result = replay(recording)
    print(f"webhook answered {result.status_code}")
    for run in result.check_runs():
        title = run.get("output", {}).get("title", "")
        print(f"check run {run['name']!r}: {run.get('conclusion', run.get('status'))}: {title}")
    print("comment:" if result.comment else "comment: none (nothing to report)")
    if result.comment:
        print(result.comment)
    if comment_out and result.comment:
        Path(comment_out).write_text(result.comment + "\n", encoding="utf-8")
    return 0
