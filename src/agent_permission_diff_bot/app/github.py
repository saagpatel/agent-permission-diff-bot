"""A small GitHub REST client for the App: installation tokens, reads, check runs, comments.

Every call goes through one ``httpx.Client`` so tests and the local replay can swap in
an in-memory GitHub with ``httpx.MockTransport``. Tokens stay inside this module and
are never logged.
"""

from __future__ import annotations

import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

import httpx
import jwt

API_VERSION = "2022-11-28"
USER_AGENT = "agent-permission-diff-bot"
MAX_PAGES = 30

# Least privilege for one run: the token is scoped to the repository the event is about.
TOKEN_PERMISSIONS = {
    "checks": "write",
    "contents": "read",
    "metadata": "read",
    "pull_requests": "write",
}


MAX_COMPARE_FILES = 300


class BlobTooLargeError(ValueError):
    """A blob is larger than the caller's limit; it was not read in full."""

    def __init__(self, sha: str) -> None:
        super().__init__(f"blob {sha[:12]} is larger than the read limit")


class GitHubError(RuntimeError):
    """A GitHub API call failed. Carries the status and path, never headers or tokens."""

    def __init__(self, method: str, path: str, status: int) -> None:
        super().__init__(f"GitHub {method} {path} returned {status}")
        self.status = status


@dataclass
class AppAuth:
    """Signs App JWTs and exchanges them for repository-scoped installation tokens."""

    app_id: str
    private_key: str = field(repr=False)
    http: httpx.Client = field(repr=False)
    _tokens: dict[tuple[int, int], tuple[str, float]] = field(default_factory=dict, repr=False)

    def app_jwt(self) -> str:
        now = int(time.time())
        payload = {"iat": now - 60, "exp": now + 540, "iss": self.app_id}
        return jwt.encode(payload, self.private_key, algorithm="RS256")

    def installation_token(self, installation_id: int, repository_id: int) -> str:
        key = (installation_id, repository_id)
        cached = self._tokens.get(key)
        if cached and cached[1] - time.time() > 120:
            return cached[0]
        path = f"/app/installations/{installation_id}/access_tokens"
        response = self.http.post(
            path,
            headers={"Authorization": f"Bearer {self.app_jwt()}"},
            json={"repository_ids": [repository_id], "permissions": TOKEN_PERMISSIONS},
        )
        if response.status_code != 201:
            raise GitHubError("POST", path, response.status_code)
        data = response.json()
        token = str(data["token"])
        expires = _parse_time(str(data.get("expires_at", ""))) or time.time() + 3000
        self._tokens[key] = (token, expires)
        return token


@dataclass
class RepoClient:
    """Calls for one repository, made with an installation token."""

    http: httpx.Client = field(repr=False)
    owner: str
    name: str
    token: str = field(repr=False)

    @property
    def full_name(self) -> str:
        return f"{self.owner}/{self.name}"

    def _request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        headers = {"Authorization": f"Bearer {self.token}"}
        response = self.http.request(method, path, headers=headers, **kwargs)
        if response.status_code >= 400:
            raise GitHubError(method, path, response.status_code)
        return response

    def _paginate(self, path: str, params: dict[str, Any] | None = None) -> Iterator[Any]:
        url: str | None = path
        query = {"per_page": 100, **(params or {})}
        for _ in range(MAX_PAGES):
            if url is None:
                return
            response = self._request("GET", url, params=query)
            yield from response.json()
            url = response.links.get("next", {}).get("url")
            query = {}

    # --- reads ---------------------------------------------------------------------------

    def tree(self, sha: str) -> tuple[dict[str, dict[str, Any]], bool]:
        """Blob entries of a commit's tree by path, and whether GitHub truncated the list."""
        data = self._request(
            "GET", f"/repos/{self.full_name}/git/trees/{sha}", params={"recursive": "1"}
        ).json()
        entries = {
            str(entry["path"]): entry
            for entry in data.get("tree", [])
            if entry.get("type") == "blob"
        }
        return entries, bool(data.get("truncated"))

    def compare(self, base_sha: str, head_sha: str) -> tuple[str, list[dict[str, Any]], bool]:
        """Merge base and changed files for exactly these two commits.

        Unlike the pull request's files list, this is fixed to the commits given, so a late
        webhook for an older push still sees that push's files. GitHub returns at most 300
        files here; the flag says when the list may be cut short.
        """
        data = self._request(
            "GET", f"/repos/{self.full_name}/compare/{base_sha}...{head_sha}"
        ).json()
        files = list(data.get("files") or [])
        return str(data["merge_base_commit"]["sha"]), files, len(files) >= MAX_COMPARE_FILES

    def pull_head(self, number: int) -> str:
        """The pull request's head commit right now, whatever order webhooks arrived in."""
        data = self._request("GET", f"/repos/{self.full_name}/pulls/{number}").json()
        return str(data["head"]["sha"])

    def open_pulls(self) -> list[dict[str, Any]]:
        return list(self._paginate(f"/repos/{self.full_name}/pulls", {"state": "open"}))

    def pulls_for_commit(self, sha: str) -> list[dict[str, Any]]:
        return list(self._paginate(f"/repos/{self.full_name}/commits/{sha}/pulls"))

    def blob_text(self, sha: str, max_bytes: int) -> str:
        """A blob's text, streamed raw and abandoned once it passes ``max_bytes``."""
        path = f"/repos/{self.full_name}/git/blobs/{sha}"
        headers = {"Authorization": f"Bearer {self.token}", "Accept": "application/vnd.github.raw"}
        with self.http.stream("GET", path, headers=headers) as response:
            if response.status_code >= 400:
                raise GitHubError("GET", path, response.status_code)
            declared = response.headers.get("content-length", "")
            if declared.isdigit() and int(declared) > max_bytes:
                raise BlobTooLargeError(sha)
            chunks: list[bytes] = []
            size = 0
            for chunk in response.iter_bytes():
                size += len(chunk)
                if size > max_bytes:
                    raise BlobTooLargeError(sha)
                chunks.append(chunk)
        return b"".join(chunks).decode("utf-8", errors="surrogateescape")

    # --- check runs ----------------------------------------------------------------------

    def create_check_run(self, name: str, head_sha: str) -> int:
        data = self._request(
            "POST",
            f"/repos/{self.full_name}/check-runs",
            json={"name": name, "head_sha": head_sha, "status": "in_progress"},
        ).json()
        return int(data["id"])

    def complete_check_run(
        self, check_run_id: int, conclusion: str, output: dict[str, Any]
    ) -> None:
        self._request(
            "PATCH",
            f"/repos/{self.full_name}/check-runs/{check_run_id}",
            json={"status": "completed", "conclusion": conclusion, "output": output},
        )

    # --- comments ------------------------------------------------------------------------

    def issue_comments(self, number: int) -> list[dict[str, Any]]:
        return list(self._paginate(f"/repos/{self.full_name}/issues/{number}/comments"))

    def create_comment(self, number: int, body: str) -> int:
        data = self._request(
            "POST", f"/repos/{self.full_name}/issues/{number}/comments", json={"body": body}
        ).json()
        return int(data["id"])

    def update_comment(self, comment_id: int, body: str) -> None:
        self._request(
            "PATCH", f"/repos/{self.full_name}/issues/comments/{comment_id}", json={"body": body}
        )


def make_http(api_url: str, transport: httpx.BaseTransport | None = None) -> httpx.Client:
    return httpx.Client(
        base_url=api_url,
        transport=transport,
        timeout=httpx.Timeout(20.0),
        headers={
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": API_VERSION,
            "User-Agent": USER_AGENT,
        },
    )


def _parse_time(value: str) -> float | None:
    from datetime import datetime

    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None
