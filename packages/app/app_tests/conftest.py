"""Integration fixtures: real Postgres 16 and Redis 7 in containers (PLAN.md §7 test pyramid).

Images default to the official ones; set AG_TEST_PG_IMAGE / AG_TEST_REDIS_IMAGE to use a mirror.
Tests that need them are skipped when Docker is unavailable.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import subprocess
import time
from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from typing import Any

import pytest
import redis as redis_sync
import redis.asyncio as aioredis
from accessguard_app.db.models import Base
from accessguard_app.db.session import make_engine, make_sessionmaker
from accessguard_app.runtime import Services
from accessguard_app.settings import Settings
from sqlalchemy import text

from .fakes import FakeGitHub, InMemoryQueue

APP_DIR = Path(__file__).resolve().parents[1]
PG_IMAGE = os.environ.get("AG_TEST_PG_IMAGE", "postgres:16")
REDIS_IMAGE = os.environ.get("AG_TEST_REDIS_IMAGE", "redis:7")
WEBHOOK_SECRET = "test-secret"


def _docker_ok() -> bool:
    if not shutil.which("docker"):
        return False
    return subprocess.run(["docker", "info"], capture_output=True).returncode == 0


@pytest.fixture(scope="session")
def containers() -> Iterator[dict[str, str]]:
    if not _docker_ok():
        pytest.skip("docker not available")
    from testcontainers.core.container import DockerContainer

    pg = (
        DockerContainer(PG_IMAGE)
        .with_env("POSTGRES_PASSWORD", "pg")
        .with_env("POSTGRES_USER", "pg")
        .with_env("POSTGRES_DB", "ag")
        .with_exposed_ports(5432)
    )
    rd = DockerContainer(REDIS_IMAGE).with_exposed_ports(6379)
    pg.start()
    rd.start()
    try:
        host = pg.get_container_host_ip()
        url = f"postgresql+asyncpg://pg:pg@{host}:{pg.get_exposed_port(5432)}/ag"
        redis_url = f"redis://{rd.get_container_host_ip()}:{rd.get_exposed_port(6379)}/0"
        deadline = time.time() + 60
        while True:
            r = pg.exec(["pg_isready", "-U", "pg", "-h", "127.0.0.1"])
            if r.exit_code == 0:
                break
            if time.time() > deadline:
                raise RuntimeError("postgres did not start")
            time.sleep(0.5)
        time.sleep(1)
        env = {**os.environ, "DATABASE_URL": url}
        subprocess.run(
            ["alembic", "-c", str(APP_DIR / "alembic.ini"), "upgrade", "head"],
            check=True,
            env=env,
            capture_output=True,
        )
        yield {"database_url": url, "redis_url": redis_url}
    finally:
        pg.stop()
        rd.stop()


@pytest.fixture
async def services(containers: dict[str, str]) -> AsyncIterator[Services]:
    engine = make_engine(containers["database_url"])
    async with engine.begin() as conn:
        tables = ", ".join(t.name for t in Base.metadata.sorted_tables)
        await conn.execute(text(f"TRUNCATE {tables} CASCADE"))
    r = aioredis.from_url(containers["redis_url"])  # type: ignore[no-untyped-call]
    await r.flushdb()
    svc = Services(
        settings=Settings(
            database_url=containers["database_url"],
            redis_url=containers["redis_url"],
            webhook_secret=WEBHOOK_SECRET,
            client_id="cid",
            app_slug="accessguard-dev",
            scan_debounce_seconds=0,
        ),
        sessions=make_sessionmaker(engine),
        redis=r,
        github=FakeGitHub(),
        queue=InMemoryQueue(),
        sync_redis=redis_sync.Redis.from_url(containers["redis_url"]),
    )
    yield svc
    await r.aclose()
    await engine.dispose()


def ctx(svc: Services) -> dict[str, Any]:
    return {"services": svc}


async def drain(
    svc: Services, *, include: set[str] | None = None, max_rounds: int = 20
) -> list[Any]:
    """Run queued jobs like a worker would, until the queue is empty."""
    from accessguard_app.jobs import reconcile, router, scan

    fns = {
        "route_delivery": router.route_delivery,
        "scan_pr": scan.scan_pr,
        "scan_push": scan.scan_push,
        "baseline_scan": scan.baseline_scan,
        "outbox_sweeper": reconcile.outbox_sweeper,
    }
    q = svc.queue
    assert isinstance(q, InMemoryQueue)
    results = []
    for _ in range(max_rounds):
        jobs = [j for j in q.jobs if include is None or j.function in include]
        for j in jobs:  # leave other jobs queued, as a worker for other queues would
            q.jobs.remove(j)
            q.ids.discard(j.job_id)
        if not jobs:
            break
        for j in jobs:
            results.append((j.function, await fns[j.function](ctx(svc), *j.args)))
    await asyncio.sleep(0)
    return results
