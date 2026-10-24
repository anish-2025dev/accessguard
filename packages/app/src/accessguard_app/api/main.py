"""HTTP API (PLAN.md §6.10): webhook intake, install linking, health and metrics. No frontend."""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import secrets
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import timedelta
from typing import Any
from urllib.parse import urlencode

from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from githubkit.webhooks import verify
from sqlalchemy import text

from accessguard_app import metrics
from accessguard_app.domain import store
from accessguard_app.runtime import Services

log = logging.getLogger("accessguard.api")
STATE_TTL = timedelta(minutes=10)


def verify_signature(secret: str, body: bytes, signature: str | None) -> bool:
    """HMAC-SHA256 over the raw body, constant-time compare (githubkit ``webhooks.verify``).
    SHA-1 signatures are rejected: githubkit would accept them, we don't."""
    if not secret or not signature or not signature.startswith("sha256="):
        return False
    return bool(verify(secret, body, signature))


def pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=")
    return verifier, challenge.decode()


def create_app(services: Services, *, manage_lifespan: bool = False) -> FastAPI:
    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        yield

    app = FastAPI(
        title="AccessGuard",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan if manage_lifespan else None,
    )
    s = services.settings

    @app.post("/webhooks/github")
    async def webhook(request: Request) -> Response:
        with metrics.WEBHOOK_LATENCY.time():
            body = await request.body()
            if not verify_signature(
                s.webhook_secret, body, request.headers.get("x-hub-signature-256")
            ):
                metrics.WEBHOOKS.labels(outcome="bad_signature").inc()
                log.warning(
                    "webhook signature invalid",
                    extra={"delivery_guid": request.headers.get("x-github-delivery")},
                )
                return JSONResponse({"error": "invalid signature"}, status_code=401)
            try:
                guid = uuid.UUID(request.headers.get("x-github-delivery", ""))
                payload: dict[str, Any] = json.loads(body)
            except ValueError:
                return JSONResponse({"error": "bad request"}, status_code=400)
            event = request.headers.get("x-github-event", "")
            inst = (payload.get("installation") or {}).get("id")
            async with services.sessions() as db:
                inserted = await store.insert_delivery(
                    db, guid, event, payload.get("action"), inst, payload
                )
            if not inserted:
                metrics.WEBHOOKS.labels(outcome="duplicate").inc()
                return JSONResponse({"status": "duplicate"}, status_code=200)
            try:
                await services.queue.enqueue("route_delivery", str(guid), job_id=f"delivery:{guid}")
            except Exception:  # the outbox sweeper re-enqueues anything left in 'received'
                log.exception(
                    "enqueue failed; delivery stays in the outbox",
                    extra={"delivery_guid": str(guid)},
                )
            metrics.WEBHOOKS.labels(outcome="accepted").inc()
            return JSONResponse({"status": "accepted"}, status_code=202)

    @app.get("/connect")
    async def connect() -> Response:
        """Start sign-in with GitHub: single-use state + PKCE (S256), stored server-side."""
        state = secrets.token_urlsafe(32)
        verifier, challenge = pkce_pair()
        async with services.sessions() as db:
            await store.create_oauth_state(db, state, verifier, "link", STATE_TTL)
        q = urlencode(
            {
                "client_id": s.client_id,
                "redirect_uri": f"{s.public_url}/callback",
                "state": state,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            }
        )
        return RedirectResponse(f"https://github.com/login/oauth/authorize?{q}", status_code=302)

    @app.get("/callback")
    async def callback(code: str = "", state: str = "") -> Response:
        async with services.sessions() as db:
            row = await store.consume_oauth_state(db, state) if state else None
        if row is None or not code:
            return HTMLResponse(
                _page("Link expired", "Start again from /connect."), status_code=400
            )
        token = await services.github.exchange_code(
            code, row.pkce_verifier, f"{s.public_url}/callback"
        )
        user = await services.github.get_authenticated_user(token)
        listed = await services.github.list_user_installations(token)
        linked = []
        async with services.sessions() as db:
            for inst in listed:  # only installations GitHub says this user can access
                if await store.get_installation(db, int(inst["id"])) is None:
                    await store.upsert_installation(db, inst)
                linked.append(int(inst["id"]))
            await store.link_user(db, int(user["id"]), str(user.get("login")), linked)
        if not linked:
            install = f"https://github.com/apps/{s.app_slug}/installations/new"
            return HTMLResponse(
                _page(
                    "No installation yet",
                    f'<a href="{install}">Install AccessGuard</a> on a '
                    "repository, then return to /connect.",
                )
            )
        return HTMLResponse(
            _page(
                "Connected",
                f"Linked {len(linked)} installation(s) to @{user.get('login')}. "
                "AccessGuard will review your next pull request.",
            )
        )

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/readyz")
    async def readyz() -> Response:
        try:
            async with services.sessions() as db:
                await db.execute(text("select 1"))
            await services.redis.ping()
        except Exception as e:
            return JSONResponse(
                {"status": "unavailable", "error": type(e).__name__}, status_code=503
            )
        return JSONResponse({"status": "ready"})

    @app.get("/metrics")
    async def prometheus() -> Response:
        body, ctype = metrics.render()
        return Response(body, media_type=ctype)

    return app


def _page(title: str, body: str) -> str:
    return (
        f"<!doctype html><meta charset=utf-8><title>{title} - AccessGuard</title>"
        f"<h1>{title}</h1><p>{body}</p>"
    )
