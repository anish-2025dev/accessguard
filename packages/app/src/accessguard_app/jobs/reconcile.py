"""Recovery crons (FR-1.3, PLAN.md §6.8): nothing is lost if the API or queue was down.

- ``outbox_sweeper`` (1 min): deliveries stored but never routed are re-enqueued.
- ``reconcile_deliveries`` (15 min): deliveries GitHub failed to deliver (we were down) are
  redelivered; GitHub then POSTs them again to the intake endpoint.
- ``reconcile_state`` (hourly): installations and repositories are diffed against GitHub.
"""

from __future__ import annotations

import logging
import uuid
from datetime import timedelta
from typing import Any

from accessguard_app import metrics
from accessguard_app.domain import store
from accessguard_app.jobs.router import resync_repos
from accessguard_app.runtime import Services

log = logging.getLogger("accessguard.reconcile")
STUCK_AFTER = timedelta(minutes=1)


async def outbox_sweeper(ctx: dict[str, Any]) -> int:
    svc: Services = ctx["services"]
    async with svc.sessions() as db:
        stuck = await store.stuck_deliveries(db, STUCK_AFTER)
    for guid in stuck:
        await svc.queue.enqueue("route_delivery", str(guid), job_id=f"delivery:{guid}")
    return len(stuck)


async def reconcile_deliveries(ctx: dict[str, Any]) -> int:
    svc: Services = ctx["services"]
    failed = await svc.github.list_failed_deliveries()
    guids = {}
    for d in failed:
        try:
            guids[uuid.UUID(str(d["guid"]))] = int(d["id"])
        except (KeyError, ValueError):
            continue
    async with svc.sessions() as db:
        known = await store.known_delivery_guids(db, list(guids))
    redelivered = 0
    for guid, delivery_id in guids.items():
        if guid in known:
            continue  # a later attempt reached us; nothing to do
        await svc.github.redeliver(delivery_id)
        redelivered += 1
    metrics.REDELIVERED.inc(redelivered)
    return redelivered


async def reconcile_state(ctx: dict[str, Any]) -> str:
    svc: Services = ctx["services"]
    remote = {int(i["id"]): i for i in await svc.github.list_app_installations()}
    async with svc.sessions() as db:
        local = {i.installation_id for i in await store.active_installations(db)}
        for iid in local - set(remote):
            await store.set_installation_state(db, iid, deleted=True)
        for inst in remote.values():
            await store.upsert_installation(db, inst)
            await store.set_installation_state(
                db, int(inst["id"]), suspended=bool(inst.get("suspended_at"))
            )
    for iid, inst in remote.items():
        if not inst.get("suspended_at"):
            try:
                await resync_repos(svc, iid, baseline=True)
            except Exception:
                log.exception("repository resync failed", extra={"installation_id": iid})
    return f"{len(remote)} installations, {len(local - set(remote))} removed"
