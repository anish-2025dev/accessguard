"""Production ASGI entry point: ``uvicorn accessguard_app.api.asgi:app``."""

from __future__ import annotations

from typing import Any

import redis.asyncio as aioredis
from arq import create_pool
from arq.connections import RedisSettings

from accessguard_app.api.main import create_app
from accessguard_app.db.session import make_engine, make_sessionmaker
from accessguard_app.github.githubkit_adapter import GitHubKitAdapter
from accessguard_app.logging_setup import configure_logging
from accessguard_app.runtime import Enqueuer, Services
from accessguard_app.settings import get_settings


class LazyArqEnqueuer:
    """Connects on first use so the API can start (and buffer to the outbox) without Redis."""

    def __init__(self, dsn: str) -> None:
        self.dsn = dsn
        self.pool: Any = None

    async def enqueue(
        self,
        function: str,
        *args: object,
        job_id: str,
        queue: str = "high",
        defer_by: float | None = None,
    ) -> bool:
        if self.pool is None:
            self.pool = await create_pool(RedisSettings.from_dsn(self.dsn))
        job = await self.pool.enqueue_job(
            function, *args, _job_id=job_id, _queue_name=f"arq:{queue}", _defer_by=defer_by
        )
        return job is not None


def build() -> object:
    configure_logging()
    s = get_settings()
    queue: Enqueuer = LazyArqEnqueuer(s.redis_url)
    services = Services(
        settings=s,
        sessions=make_sessionmaker(make_engine(s.database_url)),
        redis=aioredis.from_url(s.redis_url),  # type: ignore[no-untyped-call]
        github=GitHubKitAdapter(s),
        queue=queue,
    )
    return create_app(services)


app = build()
