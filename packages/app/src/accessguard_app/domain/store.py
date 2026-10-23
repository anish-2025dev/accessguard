"""Database operations. Every write is idempotent so any job can safely run twice."""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from datetime import UTC, date, datetime, timedelta
from typing import Any

from sqlalchemy import delete, func, select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from accessguard_app.db.models import (
    Feedback,
    FindingRow,
    Installation,
    InstallationMember,
    OAuthState,
    PRState,
    Repository,
    RuleStats,
    Scan,
    User,
    WebhookDelivery,
)


def now() -> datetime:
    return datetime.now(UTC)


# --- webhook outbox -------------------------------------------------------------------------


async def insert_delivery(
    s: AsyncSession,
    guid: uuid.UUID,
    event: str,
    action: str | None,
    installation_id: int | None,
    payload: dict[str, Any],
) -> bool:
    """Store a delivery; False if this GUID was already received (duplicate)."""
    stmt = (
        insert(WebhookDelivery)
        .values(
            delivery_guid=guid,
            event=event,
            action=action,
            installation_id=installation_id,
            payload=payload,
        )
        .on_conflict_do_nothing(index_elements=["delivery_guid"])
        .returning(WebhookDelivery.delivery_guid)
    )
    inserted = (await s.execute(stmt)).scalar_one_or_none()
    await s.commit()
    return inserted is not None


async def get_delivery(s: AsyncSession, guid: uuid.UUID) -> WebhookDelivery | None:
    return await s.get(WebhookDelivery, guid)


async def set_delivery_status(s: AsyncSession, guid: uuid.UUID, status: str) -> None:
    await s.execute(
        update(WebhookDelivery).where(WebhookDelivery.delivery_guid == guid).values(status=status)
    )
    await s.commit()


async def stuck_deliveries(s: AsyncSession, older_than: timedelta) -> Sequence[uuid.UUID]:
    rows = await s.execute(
        select(WebhookDelivery.delivery_guid)
        .where(WebhookDelivery.status == "received")
        .where(WebhookDelivery.received_at < now() - older_than)
        .limit(500)
    )
    return rows.scalars().all()


async def known_delivery_guids(s: AsyncSession, guids: Sequence[uuid.UUID]) -> set[uuid.UUID]:
    if not guids:
        return set()
    rows = await s.execute(
        select(WebhookDelivery.delivery_guid).where(WebhookDelivery.delivery_guid.in_(guids))
    )
    return set(rows.scalars().all())


# --- installations and repositories ---------------------------------------------------------


async def upsert_installation(s: AsyncSession, inst: dict[str, Any]) -> None:
    account = inst.get("account") or {}
    values = {
        "installation_id": int(inst["id"]),
        "account_id": int(account.get("id") or 0),
        "account_login": account.get("login"),
        "account_type": account.get("type"),
        "repository_selection": inst.get("repository_selection"),
        "permissions": inst.get("permissions"),
        "suspended_at": inst.get("suspended_at"),
        "deleted_at": None,
        "last_reconciled_at": now(),
    }
    stmt = insert(Installation).values(**values)
    stmt = stmt.on_conflict_do_update(
        index_elements=["installation_id"],
        set_={k: stmt.excluded[k] for k in values if k != "installation_id"},
    )
    await s.execute(stmt)
    await s.commit()


async def set_installation_state(
    s: AsyncSession, installation_id: int, *, suspended: bool | None = None, deleted: bool = False
) -> None:
    values: dict[str, Any] = {}
    if suspended is not None:
        values["suspended_at"] = now() if suspended else None
    if deleted:
        values["deleted_at"] = now()
    if values:
        await s.execute(
            update(Installation)
            .where(Installation.installation_id == installation_id)
            .values(**values)
        )
    if deleted:
        await s.execute(
            update(Repository)
            .where(Repository.installation_id == installation_id)
            .values(status="removed")
        )
    await s.commit()


async def get_installation(s: AsyncSession, installation_id: int) -> Installation | None:
    return await s.get(Installation, installation_id)


async def sync_repositories(
    s: AsyncSession, installation_id: int, repos: Sequence[dict[str, Any]]
) -> list[int]:
    """Full re-list (FR-1.2): upsert what GitHub returns, mark the rest removed. Returns new ids."""
    existing = set(
        (
            await s.execute(
                select(Repository.repo_id).where(Repository.installation_id == installation_id)
            )
        )
        .scalars()
        .all()
    )
    seen: set[int] = set()
    for r in repos:
        rid = int(r["id"])
        seen.add(rid)
        values = {
            "repo_id": rid,
            "installation_id": installation_id,
            "full_name": r.get("full_name"),
            "default_branch": r.get("default_branch"),
            "private": r.get("private"),
            "archived": r.get("archived"),
            "fork": r.get("fork"),
            "status": "paused" if r.get("archived") else "active",
        }
        stmt = insert(Repository).values(**values)
        stmt = stmt.on_conflict_do_update(
            index_elements=["repo_id"],
            set_={k: stmt.excluded[k] for k in values if k != "repo_id"},
        )
        await s.execute(stmt)
    gone = existing - seen
    if gone:
        await s.execute(
            update(Repository).where(Repository.repo_id.in_(gone)).values(status="removed")
        )
    await s.commit()
    return sorted(seen - existing)


async def get_repo(s: AsyncSession, repo_id: int) -> Repository | None:
    return await s.get(Repository, repo_id)


async def set_repo_fields(s: AsyncSession, repo_id: int, **values: Any) -> None:
    await s.execute(update(Repository).where(Repository.repo_id == repo_id).values(**values))
    await s.commit()


async def active_installations(s: AsyncSession) -> Sequence[Installation]:
    rows = await s.execute(select(Installation).where(Installation.deleted_at.is_(None)))
    return rows.scalars().all()


# --- PR state and scans -----------------------------------------------------------------------


async def upsert_pr_state(
    s: AsyncSession,
    repo_id: int,
    number: int,
    head_sha: str,
    generation: int,
    draft: bool,
    state: str,
) -> None:
    values = {
        "repo_id": repo_id,
        "pr_number": number,
        "head_sha": head_sha,
        "generation": generation,
        "draft": draft,
        "state": state,
    }
    stmt = insert(PRState).values(**values)
    stmt = stmt.on_conflict_do_update(
        index_elements=["repo_id", "pr_number"],
        set_={k: stmt.excluded[k] for k in ("head_sha", "generation", "draft", "state")},
    )
    await s.execute(stmt)
    await s.commit()


async def start_scan(
    s: AsyncSession,
    *,
    repo_id: int,
    pr_number: int | None,
    trigger: str,
    base_sha: str | None,
    head_sha: str,
    config_hash: str,
    generation: int | None,
) -> tuple[uuid.UUID, bool]:
    """Create the scan row. Returns (scan_id, created). An identical finished scan is reused."""
    existing = (
        await s.execute(
            select(Scan).where(
                Scan.repo_id == repo_id,
                Scan.head_sha == head_sha,
                Scan.trigger == trigger,
                Scan.config_hash == config_hash,
            )
        )
    ).scalar_one_or_none()
    if existing is not None and existing.status == "done":
        return existing.scan_id, False
    if pr_number is not None:
        # One active scan per PR (partial unique index): older active scans are superseded.
        await s.execute(
            update(Scan)
            .where(Scan.repo_id == repo_id, Scan.pr_number == pr_number)
            .where(Scan.status.in_(("queued", "running")))
            .values(status="superseded", finished_at=now())
        )
    if existing is not None:
        await s.execute(
            update(Scan)
            .where(Scan.scan_id == existing.scan_id)
            .values(status="running", started_at=now(), generation=generation, base_sha=base_sha)
        )
        await s.commit()
        return existing.scan_id, True
    scan_id = uuid.uuid4()
    s.add(
        Scan(
            scan_id=scan_id,
            repo_id=repo_id,
            pr_number=pr_number,
            trigger=trigger,
            base_sha=base_sha,
            head_sha=head_sha,
            config_hash=config_hash,
            generation=generation,
            status="running",
            started_at=now(),
        )
    )
    await s.commit()
    return scan_id, True


async def finish_scan(s: AsyncSession, scan_id: uuid.UUID, status: str, **values: Any) -> None:
    await s.execute(
        update(Scan)
        .where(Scan.scan_id == scan_id)
        .values(status=status, finished_at=now(), **values)
    )
    await s.commit()


async def repo_has_reported(s: AsyncSession, repo_id: int) -> bool:
    n = await s.scalar(
        select(func.count())
        .select_from(Scan)
        .where(Scan.repo_id == repo_id, Scan.status == "done", Scan.pr_number.is_not(None))
    )
    return bool(n)


# --- findings ---------------------------------------------------------------------------------


async def open_findings(
    s: AsyncSession, repo_id: int, pr_number: int | None
) -> dict[str, FindingRow]:
    q = select(FindingRow).where(FindingRow.repo_id == repo_id, FindingRow.status == "open")
    q = q.where(
        FindingRow.pr_number == pr_number
        if pr_number is not None
        else FindingRow.pr_number.is_(None)
    )
    return {f.fingerprint: f for f in (await s.execute(q)).scalars().all()}


async def finding_by_fingerprint(
    s: AsyncSession, repo_id: int, pr_number: int | None, fingerprint_prefix: str
) -> list[FindingRow]:
    q = select(FindingRow).where(
        FindingRow.repo_id == repo_id, FindingRow.fingerprint.startswith(fingerprint_prefix)
    )
    if pr_number is not None:
        q = q.where(FindingRow.pr_number == pr_number)
    return list((await s.execute(q)).scalars().all())


async def save_finding(s: AsyncSession, row: FindingRow) -> None:
    await s.merge(row)
    await s.commit()


# --- feedback and rule stats ----------------------------------------------------------------


async def add_feedback(
    s: AsyncSession, fingerprint: str, repo_id: int, actor_id: int, kind: str, reason: str
) -> bool:
    exists = await s.scalar(
        select(func.count())
        .select_from(Feedback)
        .where(
            Feedback.fingerprint == fingerprint,
            Feedback.repo_id == repo_id,
            Feedback.actor_id == actor_id,
            Feedback.kind == kind,
        )
    )
    if exists:
        return False
    s.add(
        Feedback(
            fingerprint=fingerprint, repo_id=repo_id, actor_id=actor_id, kind=kind, reason=reason
        )
    )
    await s.commit()
    return True


async def bump_rule_stat(s: AsyncSession, rule_id: str, column: str, n: int = 1) -> None:
    today = date.today().replace(day=1)  # monthly buckets
    stmt = insert(RuleStats).values(rule_id=rule_id, period=today, **{column: n})
    stmt = stmt.on_conflict_do_update(
        index_elements=["rule_id", "period"],
        set_={column: getattr(RuleStats, column) + n},
    )
    await s.execute(stmt)
    await s.commit()


async def rule_effective_fp(s: AsyncSession, rule_id: str, since: date) -> tuple[int, int]:
    """(shown, not_useful) since a date, for auto-demotion (PLAN.md §2 FB)."""
    row = (
        await s.execute(
            select(
                func.coalesce(func.sum(RuleStats.shown), 0),
                func.coalesce(func.sum(RuleStats.not_useful), 0),
            ).where(RuleStats.rule_id == rule_id, RuleStats.period >= since)
        )
    ).one()
    return int(row[0]), int(row[1])


# --- OAuth state and install linking (FR-1.1) -----------------------------------------------


async def create_oauth_state(
    s: AsyncSession, state: str, verifier: str, purpose: str, ttl: timedelta
) -> None:
    s.add(OAuthState(state=state, pkce_verifier=verifier, purpose=purpose, expires_at=now() + ttl))
    await s.commit()


async def consume_oauth_state(s: AsyncSession, state: str) -> OAuthState | None:
    """Single use: the row is deleted in the same statement that reads it."""
    row = (
        await s.execute(
            delete(OAuthState)
            .where(OAuthState.state == state, OAuthState.expires_at > now())
            .returning(OAuthState)
        )
    ).scalar_one_or_none()
    await s.commit()
    return row


async def link_user(
    s: AsyncSession, user_id: int, login: str, installation_ids: Sequence[int]
) -> None:
    stmt = insert(User).values(user_id=user_id, login=login)
    await s.execute(
        stmt.on_conflict_do_update(index_elements=["user_id"], set_={"login": stmt.excluded.login})
    )
    for iid in installation_ids:
        m = insert(InstallationMember).values(
            user_id=user_id, installation_id=iid, verified_at=now()
        )
        await s.execute(
            m.on_conflict_do_update(
                index_elements=["user_id", "installation_id"], set_={"verified_at": now()}
            )
        )
    await s.commit()
