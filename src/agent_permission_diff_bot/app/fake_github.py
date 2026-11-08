"""An in-memory GitHub for replaying recorded webhooks without network or real credentials.

It serves the handful of REST endpoints the App uses from file maps keyed by commit SHA,
checks that the App signs its JWT with the expected key, and records every check run and
comment the App writes. Used by the tests and by ``agent-permission-diff app replay``.
"""

from __future__ import annotations

import base64
import difflib
import hashlib
import json
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
import jwt

FAKE_TOKEN = "ghs_replay_installation_token"


def blob_sha(text: str) -> str:
    data = text.encode("utf-8", errors="surrogateescape")
    return hashlib.sha1(b"blob %d\0" % len(data) + data, usedforsecurity=False).hexdigest()


def commit_sha(files: dict[str, str]) -> str:
    listing = "\n".join(f"{path}:{blob_sha(text)}" for path, text in sorted(files.items()))
    return hashlib.sha1(listing.encode(), usedforsecurity=False).hexdigest()


def unified_patch(base: str, head: str) -> str:
    lines = difflib.unified_diff(base.splitlines(), head.splitlines(), lineterm="", n=3)
    return "\n".join(line for line in lines if not line.startswith(("---", "+++")))


@dataclass
class FakeGitHub:
    owner: str
    name: str
    number: int
    app_id: str
    public_key: str
    installation_id: int = 4242
    repository_id: int = 9001
    commits: dict[str, dict[str, str]] = field(default_factory=dict)
    base_sha: str = ""
    head_sha: str = ""
    check_runs: dict[int, dict[str, Any]] = field(default_factory=dict)
    comments: dict[int, dict[str, Any]] = field(default_factory=dict)
    requests: list[str] = field(default_factory=list)
    _next_id: int = 1000

    @property
    def full_name(self) -> str:
        return f"{self.owner}/{self.name}"

    def set_pull(self, base: dict[str, str], head: dict[str, str]) -> None:
        self.base_sha = commit_sha(base)
        self.head_sha = commit_sha(head)
        self.commits[self.base_sha] = dict(base)
        self.commits[self.head_sha] = dict(head)

    def add_comment(self, body: str, *, app_id: str | None = None, user: str = "someone") -> int:
        """Seed a comment, for example a human quoting the marker."""
        comment_id = self._id()
        via = {"id": int(app_id)} if app_id else None
        self.comments[comment_id] = {
            "id": comment_id,
            "body": body,
            "user": {"login": user},
            "performed_via_github_app": via,
        }
        return comment_id

    def pull_request_payload(self, action: str = "opened") -> dict[str, Any]:
        return {
            "action": action,
            "number": self.number,
            "installation": {"id": self.installation_id},
            "repository": {
                "id": self.repository_id,
                "name": self.name,
                "full_name": self.full_name,
                "private": True,
                "owner": {"login": self.owner},
            },
            "pull_request": {
                "number": self.number,
                "state": "open",
                "base": {"sha": self.base_sha, "ref": "main"},
                "head": {"sha": self.head_sha, "ref": "risky-change"},
            },
        }

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self._handle)

    # --- request handling ----------------------------------------------------------------

    def _id(self) -> int:
        self._next_id += 1
        return self._next_id

    def _handle(self, request: httpx.Request) -> httpx.Response:
        method, path = request.method, request.url.path
        self.requests.append(f"{method} {path}")
        auth = request.headers.get("authorization", "")
        if path.startswith("/app/installations/") and path.endswith("/access_tokens"):
            return self._token(auth, request)
        if auth != f"Bearer {FAKE_TOKEN}":
            return httpx.Response(401, json={"message": "Bad credentials"})
        repo = f"/repos/{self.full_name}"
        if not path.startswith(repo + "/"):
            return httpx.Response(404, json={"message": "Not Found"})
        rest = path[len(repo) :]
        body = json.loads(request.content) if request.content else {}
        routes: list[tuple[str, str, Any]] = [
            ("GET", rf"/pulls/{self.number}/files", self._pull_files),
            ("GET", r"/git/trees/(?P<sha>[0-9a-f]+)", self._tree),
            ("GET", r"/git/blobs/(?P<sha>[0-9a-f]+)", self._blob),
            ("POST", r"/check-runs", self._create_run),
            ("PATCH", r"/check-runs/(?P<id>\d+)", self._update_run),
            ("GET", rf"/issues/{self.number}/comments", self._list_comments),
            ("POST", rf"/issues/{self.number}/comments", self._create_comment),
            ("PATCH", r"/issues/comments/(?P<id>\d+)", self._update_comment),
        ]
        for verb, pattern, handler in routes:
            match = re.fullmatch(pattern, rest)
            if verb == method and match:
                response: httpx.Response = handler(body=body, **match.groupdict())
                return response
        return httpx.Response(404, json={"message": "Not Found"})

    def _token(self, auth: str, request: httpx.Request) -> httpx.Response:
        try:
            claims = jwt.decode(auth.removeprefix("Bearer "), self.public_key, algorithms=["RS256"])
        except jwt.PyJWTError:
            return httpx.Response(401, json={"message": "A JSON web token could not be decoded"})
        if str(claims.get("iss")) != self.app_id:
            return httpx.Response(401, json={"message": "Integration not found"})
        body = json.loads(request.content or b"{}")
        if not request.url.path.startswith(f"/app/installations/{self.installation_id}/"):
            return httpx.Response(404, json={"message": "Not Found"})
        if body.get("repository_ids") != [self.repository_id]:
            return httpx.Response(422, json={"message": "token must be scoped to the repository"})
        return httpx.Response(201, json={"token": FAKE_TOKEN, "expires_at": "2099-01-01T00:00:00Z"})

    def _pull_files(self, body: Any) -> httpx.Response:
        base, head = self.commits[self.base_sha], self.commits[self.head_sha]
        files = []
        for path in sorted(set(base) | set(head)):
            before, after = base.get(path), head.get(path)
            if before == after:
                continue
            status = "added" if before is None else "removed" if after is None else "modified"
            entry: dict[str, Any] = {
                "filename": path,
                "status": status,
                "sha": blob_sha(after) if after is not None else blob_sha(before or ""),
                "patch": unified_patch(before or "", after or ""),
            }
            files.append(entry)
        return httpx.Response(200, json=files)

    def _tree(self, body: Any, sha: str) -> httpx.Response:
        files = self.commits.get(sha)
        if files is None:
            return httpx.Response(404, json={"message": "Not Found"})
        tree = [
            {
                "path": path,
                "mode": "100644",
                "type": "blob",
                "sha": blob_sha(text),
                "size": len(text.encode("utf-8", errors="surrogateescape")),
            }
            for path, text in sorted(files.items())
        ]
        return httpx.Response(200, json={"sha": sha, "tree": tree, "truncated": False})

    def _blob(self, body: Any, sha: str) -> httpx.Response:
        for files in self.commits.values():
            for text in files.values():
                if blob_sha(text) == sha:
                    content = base64.b64encode(text.encode("utf-8", errors="surrogateescape"))
                    return httpx.Response(
                        200, json={"sha": sha, "encoding": "base64", "content": content.decode()}
                    )
        return httpx.Response(404, json={"message": "Not Found"})

    def _create_run(self, body: Any) -> httpx.Response:
        run_id = self._id()
        self.check_runs[run_id] = {"id": run_id, **body}
        return httpx.Response(201, json={"id": run_id})

    def _update_run(self, body: Any, id: str) -> httpx.Response:
        run = self.check_runs.get(int(id))
        if run is None:
            return httpx.Response(404, json={"message": "Not Found"})
        run.update(body)
        return httpx.Response(200, json=run)

    def _list_comments(self, body: Any) -> httpx.Response:
        return httpx.Response(200, json=list(self.comments.values()))

    def _create_comment(self, body: Any) -> httpx.Response:
        comment_id = self.add_comment(str(body["body"]), app_id=self.app_id, user="apdb[bot]")
        return httpx.Response(201, json=self.comments[comment_id])

    def _update_comment(self, body: Any, id: str) -> httpx.Response:
        comment = self.comments.get(int(id))
        if comment is None:
            return httpx.Response(404, json={"message": "Not Found"})
        comment["body"] = str(body["body"])
        return httpx.Response(200, json=comment)


def read_tree_dir(root: Path) -> dict[str, str]:
    """A directory of fixture files as {posix path: text}."""
    return {
        path.relative_to(root).as_posix(): path.read_text(encoding="utf-8")
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def read_git_tree(repo: Path, ref: str) -> dict[str, str]:
    """Every text file at a local Git ref, for replaying a demo branch as a pull request."""
    names = subprocess.run(
        ["git", "-C", str(repo), "ls-tree", "-r", "--name-only", ref],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.splitlines()
    files: dict[str, str] = {}
    for name in names:
        shown = subprocess.run(
            ["git", "-C", str(repo), "show", f"{ref}:{name}"], check=True, capture_output=True
        )
        try:
            files[name] = shown.stdout.decode("utf-8")
        except UnicodeDecodeError:
            continue
    return files
