"""Postgres persistence for the runtime verifier (PLAN.md §6.7 ``verifier_credentials`` /
``verifier_audit``). Rows hold ciphertext and wrapped data keys only."""

from __future__ import annotations

import uuid
from typing import Any

from accessguard_verifier.vault import Sealed
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from accessguard_app.db.models import VerifierAudit, VerifierCredential


class DbCredentialStore:
    def __init__(self, sessions: async_sessionmaker[AsyncSession]) -> None:
        self.sessions = sessions

    async def put(self, repo_id: int, label: str, sealed: Sealed) -> None:
        async with self.sessions() as s:
            await s.merge(
                VerifierCredential(
                    repo_id=repo_id,
                    label=label,
                    ciphertext=sealed.ciphertext,
                    wrapped_dek=sealed.wrapped_dek,
                )
            )
            await s.commit()

    async def get(self, repo_id: int, label: str) -> Sealed | None:
        async with self.sessions() as s:
            row = (
                await s.execute(
                    select(VerifierCredential).where(
                        VerifierCredential.repo_id == repo_id, VerifierCredential.label == label
                    )
                )
            ).scalar_one_or_none()
        if row is None or row.ciphertext is None or row.wrapped_dek is None:
            return None
        return Sealed(row.ciphertext, row.wrapped_dek)

    async def delete(self, repo_id: int, label: str) -> None:
        async with self.sessions() as s:
            await s.execute(
                delete(VerifierCredential).where(
                    VerifierCredential.repo_id == repo_id, VerifierCredential.label == label
                )
            )
            await s.commit()


class DbAudit:
    def __init__(self, sessions: async_sessionmaker[AsyncSession]) -> None:
        self.sessions = sessions

    async def record(self, entry: dict[str, Any]) -> None:
        async with self.sessions() as s:
            s.add(
                VerifierAudit(
                    scan_id=uuid.UUID(entry["scan_id"]),
                    tool=entry["tool"],
                    method=entry["method"],
                    url=entry["url"],
                    status=entry["status"],
                    decision=entry["decision"],
                )
            )
            await s.commit()
