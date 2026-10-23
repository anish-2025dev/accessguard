"""Alembic environment (async). URL from DATABASE_URL."""

from __future__ import annotations

import asyncio
import os

from accessguard_app.db.models import Base
from alembic import context
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import create_async_engine

target_metadata = Base.metadata


def _url() -> str:
    return os.environ.get("DATABASE_URL") or context.config.get_main_option("sqlalchemy.url") or ""


def _run(connection: Connection) -> None:
    context.configure(connection=connection, target_metadata=target_metadata)
    with context.begin_transaction():
        context.run_migrations()


async def _online() -> None:
    engine = create_async_engine(_url())
    async with engine.connect() as conn:
        await conn.run_sync(_run)
    await engine.dispose()


if context.is_offline_mode():
    context.configure(url=_url(), target_metadata=target_metadata, literal_binds=True)
    with context.begin_transaction():
        context.run_migrations()
else:
    asyncio.run(_online())
