"""The GitHub App webhook server.

``POST /webhook`` verifies GitHub's HMAC signature, answers right away, and runs the
checks in a worker thread. Nothing from the pull request is executed: the checks read
file contents through the API, so fork pull requests are safe to analyze.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import threading
from collections import OrderedDict

import httpx
from fastapi import BackgroundTasks, FastAPI, Request, Response
from fastapi.responses import JSONResponse

from agent_permission_diff_bot.app.github import AppAuth, RepoClient, make_http
from agent_permission_diff_bot.app.pipeline import (
    PullTarget,
    resolve_target,
    run_checks,
    target_from_event,
)
from agent_permission_diff_bot.app.settings import AppSettings

log = logging.getLogger(__name__)

MAX_BODY_BYTES = 25 * 1024 * 1024
MAX_TRACKED_PULLS = 1024


def verify_signature(secret: str, body: bytes, header: str) -> bool:
    if not header.startswith("sha256="):
        return False
    expected = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, header.removeprefix("sha256="))


class PullLocks:
    """One lock per pull request, remembering only the most recent ``limit`` of them.

    The oldest idle locks are forgotten first; a held lock is never dropped, so two runs
    for one pull request can never overlap even after many other pull requests.
    """

    def __init__(self, limit: int = MAX_TRACKED_PULLS) -> None:
        self.limit = limit
        self._locks: OrderedDict[tuple[int, int], threading.Lock] = OrderedDict()
        self._guard = threading.Lock()

    def lock_for(self, repository_id: int, number: int) -> threading.Lock:
        key = (repository_id, number)
        with self._guard:
            lock = self._locks.pop(key, None) or threading.Lock()
            self._locks[key] = lock
            for old_key in list(self._locks):
                if len(self._locks) <= self.limit:
                    break
                if old_key != key and not self._locks[old_key].locked():
                    del self._locks[old_key]
            return lock

    def __len__(self) -> int:
        return len(self._locks)


def create_app(settings: AppSettings, transport: httpx.BaseTransport | None = None) -> FastAPI:
    http = make_http(settings.api_url, transport)
    auth = AppAuth(app_id=settings.app_id, private_key=settings.private_key, http=http)
    locks = PullLocks()
    app = FastAPI(title="Agent Permission Diff Bot", docs_url=None, redoc_url=None)

    def process(target: PullTarget) -> None:
        try:
            token = auth.installation_token(target.installation_id, target.repository_id)
            repo = RepoClient(http=http, owner=target.owner, name=target.name, token=token)
            resolved = resolve_target(repo, target)
            if resolved is None:
                log.info("No open pull request for %s; nothing to re-run", target.head_sha[:7])
                return
            # One run per pull request at a time; only the PR's live head writes the comment.
            with locks.lock_for(resolved.repository_id, resolved.number):
                outcome = run_checks(
                    repo,
                    resolved,
                    app_id=settings.app_id,
                    guard_fail_on=settings.guard_fail_on,
                    swallowed_fail_on=settings.swallowed_fail_on,
                    is_current=lambda: repo.pull_head(resolved.number) == resolved.head_sha,
                )
        except Exception:
            log.exception("Checks for %s/%s#%s failed", target.owner, target.name, target.number)
            return
        log.info(
            "Checked %s/%s#%s at %s: %s, comment %s",
            resolved.owner,
            resolved.name,
            resolved.number,
            resolved.head_sha[:7],
            outcome.conclusions,
            outcome.comment_action,
        )

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/webhook")
    async def webhook(request: Request, background: BackgroundTasks) -> Response:
        declared = request.headers.get("content-length", "")
        if declared.isdigit() and int(declared) > MAX_BODY_BYTES:
            return JSONResponse({"error": "payload too large"}, status_code=413)
        chunks: list[bytes] = []
        size = 0
        async for chunk in request.stream():
            size += len(chunk)
            if size > MAX_BODY_BYTES:
                return JSONResponse({"error": "payload too large"}, status_code=413)
            chunks.append(chunk)
        body = b"".join(chunks)
        signature = request.headers.get("x-hub-signature-256", "")
        if not verify_signature(settings.webhook_secret, body, signature):
            return JSONResponse({"error": "bad signature"}, status_code=401)
        event = request.headers.get("x-github-event", "")
        if event == "ping":
            return JSONResponse({"status": "pong"})
        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            return JSONResponse({"error": "body is not JSON"}, status_code=400)
        target = target_from_event(event, payload) if isinstance(payload, dict) else None
        if target is None:
            return JSONResponse({"status": "ignored"}, status_code=202)
        background.add_task(process, target)
        return JSONResponse({"status": "queued", "head": target.head_sha[:7]}, status_code=202)

    return app


def main_serve(host: str, port: int) -> int:
    import uvicorn

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    settings = AppSettings.from_env()
    uvicorn.run(create_app(settings), host=host, port=port, log_level="info")
    return 0
