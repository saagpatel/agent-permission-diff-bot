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
from collections.abc import Callable

import httpx
from fastapi import BackgroundTasks, FastAPI, Request, Response
from fastapi.responses import JSONResponse

from agent_permission_diff_bot.app.github import AppAuth, RepoClient, make_http
from agent_permission_diff_bot.app.pipeline import (
    PayloadError,
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
    try:
        given = header.removeprefix("sha256=").encode("ascii")
    except UnicodeEncodeError:
        return False  # not a hex digest; compare_digest would raise on non-ASCII text
    expected = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest().encode("ascii")
    return hmac.compare_digest(expected, given)


class PullRuns:
    """Runs for one pull request happen one at a time, without parking worker threads.

    If a run for the pull request is in progress, ``submit`` queues the new job and
    returns at once; the thread already running the pull request works through the queue.
    A job with the same key (head commit and base branch) replaces a queued one rather
    than piling up. Nothing is kept for a pull request once its queue is empty.
    """

    def __init__(self) -> None:
        self._guard = threading.Lock()
        self._running: set[tuple[int, int]] = set()
        self._pending: dict[tuple[int, int], OrderedDict[tuple[str, str], Callable[[], None]]] = {}

    def submit(
        self, pull: tuple[int, int], job_key: tuple[str, str], job: Callable[[], None]
    ) -> bool:
        """Run ``job`` now, or queue it; returns False when it was queued."""
        with self._guard:
            if pull in self._running:
                self._pending.setdefault(pull, OrderedDict())[job_key] = job
                return False
            self._running.add(pull)
        next_job: Callable[[], None] | None = job
        while next_job is not None:
            try:
                next_job()
            except Exception:
                log.exception("A queued run for pull request %s failed", pull)
            with self._guard:
                queue = self._pending.get(pull)
                if queue:
                    _, next_job = queue.popitem(last=False)
                    if not queue:
                        del self._pending[pull]
                else:
                    self._running.discard(pull)
                    next_job = None
        return True

    def busy(self) -> int:
        with self._guard:
            return len(self._running) + sum(len(q) for q in self._pending.values())


def create_app(settings: AppSettings, transport: httpx.BaseTransport | None = None) -> FastAPI:
    http = make_http(settings.api_url, transport)
    auth = AppAuth(app_id=settings.app_id, private_key=settings.private_key, http=http)
    runs = PullRuns()
    app = FastAPI(title="Agent Permission Diff Bot", docs_url=None, redoc_url=None)

    def process(target: PullTarget) -> None:
        try:
            token = auth.installation_token(target.installation_id, target.repository_id)
            repo = RepoClient(http=http, owner=target.owner, name=target.name, token=token)
            resolved = resolve_target(repo, target)
        except Exception:
            log.exception("Checks for %s/%s#%s failed", target.owner, target.name, target.number)
            return
        if resolved is None:
            log.info("No open pull request for %s; nothing to re-run", target.head_sha[:7])
            return

        def run() -> None:
            outcome = run_checks(
                repo,
                resolved,
                app_id=settings.app_id,
                guard_fail_on=settings.guard_fail_on,
                swallowed_fail_on=settings.swallowed_fail_on,
            )
            log.info(
                "Checked %s/%s#%s at %s: %s, comment %s",
                resolved.owner,
                resolved.name,
                resolved.number,
                resolved.head_sha[:7],
                outcome.conclusions,
                outcome.comment_action,
            )

        # One run per pull request at a time, queued rather than waited for.
        runs.submit(
            (resolved.repository_id, resolved.number),
            (resolved.head_sha, resolved.base_ref),
            run,
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
        except ValueError:  # JSONDecodeError, or UnicodeDecodeError for non-UTF-8 bytes
            return JSONResponse({"error": "body is not JSON"}, status_code=400)
        if not isinstance(payload, dict):
            return JSONResponse({"error": "body is not a JSON object"}, status_code=400)
        try:
            target = target_from_event(event, payload)
        except PayloadError:
            # The detail goes to the log only; the response never echoes it.
            log.warning("Rejected a %s webhook with a malformed payload", event, exc_info=True)
            return JSONResponse({"error": "payload is missing required fields"}, status_code=400)
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
