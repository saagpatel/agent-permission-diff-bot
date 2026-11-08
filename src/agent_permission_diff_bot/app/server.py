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
from collections import defaultdict

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


def verify_signature(secret: str, body: bytes, header: str) -> bool:
    if not header.startswith("sha256="):
        return False
    expected = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, header.removeprefix("sha256="))


def create_app(settings: AppSettings, transport: httpx.BaseTransport | None = None) -> FastAPI:
    http = make_http(settings.api_url, transport)
    auth = AppAuth(app_id=settings.app_id, private_key=settings.private_key, http=http)
    locks: defaultdict[tuple[int, int], threading.Lock] = defaultdict(threading.Lock)
    latest: dict[tuple[int, int], str] = {}
    state_guard = threading.Lock()
    app = FastAPI(title="Agent Permission Diff Bot", docs_url=None, redoc_url=None)

    def remember(target: PullTarget, *, newest: bool) -> None:
        with state_guard:
            key = (target.repository_id, target.number)
            if newest or key not in latest:
                latest[key] = target.head_sha

    def is_current(target: PullTarget) -> bool:
        with state_guard:
            return latest.get((target.repository_id, target.number)) == target.head_sha

    def process(target: PullTarget) -> None:
        try:
            token = auth.installation_token(target.installation_id, target.repository_id)
            repo = RepoClient(http=http, owner=target.owner, name=target.name, token=token)
            resolved = resolve_target(repo, target)
            if resolved is None:
                log.info("No open pull request for %s; nothing to re-run", target.head_sha[:7])
                return
            remember(resolved, newest=False)
            with state_guard:
                lock = locks[(resolved.repository_id, resolved.number)]
            # One run per pull request at a time; only the newest push may write the comment.
            with lock:
                outcome = run_checks(
                    repo,
                    resolved,
                    app_id=settings.app_id,
                    guard_fail_on=settings.guard_fail_on,
                    swallowed_fail_on=settings.swallowed_fail_on,
                    is_current=lambda: is_current(resolved),
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
        if target.number and event == "pull_request":
            remember(target, newest=True)
        background.add_task(process, target)
        return JSONResponse({"status": "queued", "head": target.head_sha[:7]}, status_code=202)

    return app


def main_serve(host: str, port: int) -> int:
    import uvicorn

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    settings = AppSettings.from_env()
    uvicorn.run(create_app(settings), host=host, port=port, log_level="info")
    return 0
