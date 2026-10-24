"""Shared services for the API and workers, plus small Redis-backed primitives (PLAN.md §6.9)."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Protocol

import redis as redis_sync
import redis.asyncio as aioredis
from authgraph.llm.judge import Judge
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from accessguard_app.github.port import GitHubPort
from accessguard_app.settings import Settings

SUMMARY_TTL = 30 * 24 * 3600  # summaries keyed by blob SHA expire in 30 days (PLAN.md §5)
PR_KEY_TTL = 7 * 24 * 3600


class Enqueuer(Protocol):
    async def enqueue(
        self,
        function: str,
        *args: Any,
        job_id: str,
        queue: str = "high",
        defer_by: float | None = None,
    ) -> bool: ...


class ArqEnqueuer:
    """``ArqRedis.enqueue_job`` (arq 0.28.0: ``_job_id``, ``_queue_name``, ``_defer_by``).
    Returns False when a job with the same id already exists (ARQ dedup)."""

    def __init__(self, pool: Any) -> None:
        self.pool = pool

    async def enqueue(
        self,
        function: str,
        *args: Any,
        job_id: str,
        queue: str = "high",
        defer_by: float | None = None,
    ) -> bool:
        job = await self.pool.enqueue_job(
            function, *args, _job_id=job_id, _queue_name=f"arq:{queue}", _defer_by=defer_by
        )
        return job is not None


@dataclass
class Services:
    settings: Settings
    sessions: async_sessionmaker[AsyncSession]
    redis: aioredis.Redis
    github: GitHubPort
    queue: Enqueuer
    sync_redis: redis_sync.Redis | None = None
    extra: dict[str, Any] = field(default_factory=dict)
    judge: Judge | None = None  # LLM triage; None when no model is configured


# --- PR generation counter (FR-2.6) -------------------------------------------------------------


def gen_key(repo_id: int, pr: int) -> str:
    return f"pr:{repo_id}:{pr}:gen"


async def bump_generation(r: aioredis.Redis, repo_id: int, pr: int, head_sha: str) -> int:
    gen = int(await r.incr(gen_key(repo_id, pr)))
    await r.expire(gen_key(repo_id, pr), PR_KEY_TTL)
    await r.set(f"pr:{repo_id}:{pr}:head", head_sha, ex=PR_KEY_TTL)
    return gen


async def current_generation(r: aioredis.Redis, repo_id: int, pr: int) -> int:
    v = await r.get(gen_key(repo_id, pr))
    return int(v or 0)


# --- token buckets (FR-2.4 command rate limits, per-installation budgets) ----------------------


async def take_token(r: aioredis.Redis, key: str, capacity: int, per_seconds: int) -> bool:
    """Fixed-window bucket: at most ``capacity`` takes per window. Atomic via INCR."""
    window = int(time.time() // per_seconds)
    k = f"{key}:{window}"
    n = int(await r.incr(k))
    if n == 1:
        await r.expire(k, per_seconds)
    return n <= capacity


# --- authgraph summary cache in Redis -----------------------------------------------------------


class RedisSummaryCache:
    """authgraph ``SummaryCache`` (sync: the engine runs in a worker thread)."""

    def __init__(self, client: redis_sync.Redis) -> None:
        self.r = client

    def get(self, key: str) -> str | None:
        v = self.r.get(key)
        return v.decode() if isinstance(v, bytes) else v  # type: ignore[return-value]

    def set(self, key: str, value: str) -> None:
        self.r.set(key, value, ex=SUMMARY_TTL)
