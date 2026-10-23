"""ARQ worker settings (ADR 004). Two queues so PR scans never wait behind baselines.

    arq accessguard_app.jobs.worker.HighWorker
    arq accessguard_app.jobs.worker.LowWorker

Verified against arq 0.28.0: ``cron(coroutine, minute=..., run_at_startup=...)``,
``Worker(functions, queue_name, cron_jobs, allow_abort_jobs, ...)``, ``func(coroutine,
max_tries=...)``, ``Retry(defer=...)``.
"""

from __future__ import annotations

import functools
from collections.abc import Awaitable, Callable
from typing import Any, ClassVar

import redis
import redis.asyncio as aioredis
from accessguard_verifier.vault import Vault, private_key_from_env
from arq import Retry, cron
from arq.connections import RedisSettings
from arq.worker import func
from authgraph.llm.litellm_judge import LiteLLMJudge

from accessguard_app.db.session import make_engine, make_sessionmaker
from accessguard_app.domain.verifier_store import DbCredentialStore
from accessguard_app.github.githubkit_adapter import GitHubKitAdapter
from accessguard_app.github.port import RateLimited
from accessguard_app.jobs import reconcile, router, scan, verify
from accessguard_app.logging_setup import configure_logging
from accessguard_app.runtime import ArqEnqueuer, Services
from accessguard_app.settings import get_settings

Job = Callable[..., Awaitable[Any]]


def _job(fn: Job) -> Any:
    return retry_on_rate_limit(fn)  # arq types WorkerCoroutine narrowly; ours are compatible


def retry_on_rate_limit(fn: Job) -> Job:
    @functools.wraps(fn)
    async def wrapper(ctx: dict[str, Any], *args: Any) -> Any:
        try:
            return await fn(ctx, *args)
        except RateLimited as e:  # honour retry-after / reset (PLAN.md §6.15)
            raise Retry(defer=e.retry_after) from e

    return wrapper


async def startup(ctx: dict[str, Any]) -> None:
    configure_logging()
    s = get_settings()
    engine = make_engine(s.database_url)
    ctx["engine"] = engine
    ctx["services"] = Services(
        settings=s,
        sessions=make_sessionmaker(engine),
        redis=aioredis.from_url(s.redis_url),  # type: ignore[no-untyped-call]
        github=GitHubKitAdapter(s),
        queue=ArqEnqueuer(ctx["redis"]),
        sync_redis=redis.Redis.from_url(s.redis_url),
        judge=LiteLLMJudge(s.llm_model) if s.llm_model else None,
    )


async def shutdown(ctx: dict[str, Any]) -> None:
    await ctx["engine"].dispose()


def _redis() -> RedisSettings:
    return RedisSettings.from_dsn(get_settings().redis_url)


class HighWorker:
    queue_name = "arq:high"
    functions: ClassVar[list[Any]] = [
        func(_job(router.route_delivery), name="route_delivery", max_tries=5),
        func(_job(scan.scan_pr), name="scan_pr", max_tries=3, timeout=600),
        func(_job(scan.scan_push), name="scan_push", max_tries=3, timeout=600),
    ]
    cron_jobs: ClassVar[list[Any]] = [
        cron(reconcile.outbox_sweeper, second=0, run_at_startup=True),
        cron(reconcile.reconcile_deliveries, minute={0, 15, 30, 45}, second=5),
        cron(reconcile.reconcile_state, minute=7, second=10),
    ]
    on_startup = startup
    on_shutdown = shutdown
    allow_abort_jobs = True
    redis_settings = _redis()


class LowWorker:
    queue_name = "arq:low"
    functions: ClassVar[list[Any]] = [
        func(_job(scan.baseline_scan), name="baseline_scan", max_tries=3, timeout=1800),
    ]
    on_startup = startup
    on_shutdown = shutdown
    max_jobs = 2  # per-installation fairness is enforced by the token budget in baseline_scan
    redis_settings = _redis()


async def verifier_startup(ctx: dict[str, Any]) -> None:
    """The verifier worker is the only process given the vault's private key (ADR 015)."""
    await startup(ctx)
    svc: Services = ctx["services"]
    ctx["vault"] = Vault(private_key_from_env(), DbCredentialStore(svc.sessions))


class VerifyWorker:
    queue_name = "arq:verify"
    functions: ClassVar[list[Any]] = [
        func(_job(verify.verify_findings), name="verify_findings", max_tries=2, timeout=600),
    ]
    on_startup = verifier_startup
    on_shutdown = shutdown
    max_jobs = 2
    redis_settings = _redis()
