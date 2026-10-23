"""``route_delivery``: turn a stored webhook into work (PLAN.md §6.8, §6.12).

Payloads are triggers only: PR state is always re-fetched live (never trust payload order), the
generation counter supersedes older scans, and every enqueue carries a work-key job id so a
duplicate delivery or a re-run produces the same job.
"""

from __future__ import annotations

import logging
import re
import uuid
from typing import Any

from authgraph.guards.config import CONFIG_FILE, parse_config

from accessguard_app.domain import store
from accessguard_app.runtime import Services, bump_generation, take_token

log = logging.getLogger("accessguard.router")
PR_ACTIONS = {"opened", "synchronize", "reopened", "ready_for_review"}
COMMAND = re.compile(r"^\s*@accessguard\s+(scan|ignore)\b\s*(.*)$", re.I | re.M)
WRITE_PERMISSIONS = {"admin", "maintain", "write"}


async def route_delivery(ctx: dict[str, Any], guid: str) -> str:
    svc: Services = ctx["services"]
    gid = uuid.UUID(guid)
    async with svc.sessions() as db:
        d = await store.get_delivery(db, gid)
    if d is None:
        return "missing"
    if d.status == "routed":
        return "already routed"  # idempotent: duplicate job runs are no-ops
    payload: dict[str, Any] = d.payload or {}
    handler = HANDLERS.get(d.event or "")
    outcome = await handler(svc, d.action or "", payload) if handler else "ignored event"
    async with svc.sessions() as db:
        await store.set_delivery_status(db, gid, "routed")
    log.info("routed", extra={"delivery_guid": guid, "event": d.event, "outcome": outcome})
    return outcome


async def on_installation(svc: Services, action: str, p: dict[str, Any]) -> str:
    inst = p["installation"]
    iid = int(inst["id"])
    async with svc.sessions() as db:
        if action == "deleted":
            await store.set_installation_state(db, iid, deleted=True)
            return "installation deleted"
        if action in ("suspend", "unsuspend"):
            await store.upsert_installation(db, inst)
            await store.set_installation_state(db, iid, suspended=action == "suspend")
            return f"installation {action}"
        await store.upsert_installation(db, inst)
    return await resync_repos(svc, iid, baseline=action == "created")


async def on_installation_repositories(svc: Services, action: str, p: dict[str, Any]) -> str:
    # The payload is only a trigger: re-list from GET /installation/repositories (FR-1.2).
    return await resync_repos(svc, int(p["installation"]["id"]), baseline=True)


async def resync_repos(svc: Services, iid: int, *, baseline: bool) -> str:
    repos = await svc.github.list_installation_repos(iid)
    async with svc.sessions() as db:
        new = await store.sync_repositories(db, iid, repos)
    if baseline:
        by_id = {int(r["id"]): r for r in repos}
        for rid in new:
            r = by_id[rid]
            if r.get("archived"):
                continue
            # Low-priority baseline, keyed on the default branch (resolved by the job).
            await svc.queue.enqueue(
                "baseline_scan",
                rid,
                r.get("default_branch") or "HEAD",
                job_id=f"baseline:{rid}:{r.get('default_branch')}",
                queue="low",
            )
    return f"{len(repos)} repositories, {len(new)} new"


async def on_pull_request(svc: Services, action: str, p: dict[str, Any]) -> str:
    if action not in PR_ACTIONS:
        return f"ignored action {action}"
    repo_id = int(p["repository"]["id"])
    number = int(p["pull_request"]["number"])
    return await schedule_pr_scan(svc, repo_id, number, force=False)


async def schedule_pr_scan(svc: Services, repo_id: int, number: int, *, force: bool) -> str:
    async with svc.sessions() as db:
        repo = await store.get_repo(db, repo_id)
    if repo is None or repo.status != "active" or repo.installation_id is None:
        return "repository not active"
    live = await svc.github.get_pull(repo.installation_id, repo.full_name or "", number)
    if live.get("state") != "open":
        return "pull request not open"
    head = live["head"]["sha"]
    draft = bool(live.get("draft"))
    if draft and not force:
        raw = await svc.github.get_file(
            repo.installation_id, repo.full_name or "", CONFIG_FILE, live["base"]["sha"]
        )
        if not parse_config(raw).scan_drafts:
            return "draft skipped"  # FR-2.3: ready_for_review or @accessguard scan triggers
    gen = await bump_generation(svc.redis, repo_id, number, head)
    async with svc.sessions() as db:
        await store.upsert_pr_state(db, repo_id, number, head, gen, draft, "open")
    suffix = f":g{gen}" if force else ""
    await svc.queue.enqueue(
        "scan_pr",
        repo_id,
        number,
        head,
        gen,
        job_id=f"scan:{repo_id}:{number}:{head}{suffix}",
        defer_by=svc.settings.scan_debounce_seconds,
    )
    return f"scan scheduled g{gen}"


async def on_push(svc: Services, action: str, p: dict[str, Any]) -> str:
    repo = p["repository"]
    branch = repo.get("default_branch")
    if p.get("ref") != f"refs/heads/{branch}" or p.get("deleted"):
        return "not a push to the default branch"
    before, after = p["before"], p["after"]
    if set(before) == {"0"}:
        return "branch created"
    await svc.queue.enqueue(
        "scan_push", int(repo["id"]), before, after, job_id=f"push:{repo['id']}:{after}"
    )
    return "push scan scheduled"


async def on_check_run(svc: Services, action: str, p: dict[str, Any]) -> str:
    if action != "rerequested":
        return f"ignored action {action}"
    prs = p["check_run"].get("pull_requests") or []
    if not prs:
        return "no pull request"
    return await schedule_pr_scan(
        svc, int(p["repository"]["id"]), int(prs[0]["number"]), force=True
    )


async def on_issue_comment(svc: Services, action: str, p: dict[str, Any]) -> str:
    """``@accessguard scan`` / ``@accessguard ignore <id> <reason>`` (FR-2.4, FB)."""
    if action != "created" or "pull_request" not in p.get("issue", {}):
        return "not a PR comment"
    sender = p["sender"]
    if sender.get("type") == "Bot" or sender.get("login") == svc.settings.bot_login:
        return "bot comment ignored"  # bot-loop guard
    m = COMMAND.search(p["comment"].get("body") or "")
    if not m:
        return "no command"
    repo_id = int(p["repository"]["id"])
    number = int(p["issue"]["number"])
    if not (
        await take_token(svc.redis, f"cmd:pr:{repo_id}:{number}", 5, 60)
        and await take_token(svc.redis, f"cmd:user:{sender['id']}", 30, 3600)
    ):
        return "rate limited"
    async with svc.sessions() as db:
        repo = await store.get_repo(db, repo_id)
    if repo is None or repo.installation_id is None:
        return "repository not active"
    perm = await svc.github.get_permission(
        repo.installation_id, repo.full_name or "", sender["login"]
    )
    if perm not in WRITE_PERMISSIONS:
        return "commenter lacks write permission"
    verb, rest = m.group(1).lower(), m.group(2).strip()
    if verb == "scan":
        return await schedule_pr_scan(svc, repo_id, number, force=True)
    fp_prefix, _, reason = rest.partition(" ")
    if len(fp_prefix) < 6:
        return "ignore needs a finding id"
    async with svc.sessions() as db:
        rows = await store.finding_by_fingerprint(db, repo_id, number, fp_prefix)
        for row in rows:
            row.status = "dismissed"
            await store.save_finding(db, row)
            if await store.add_feedback(
                db,
                row.fingerprint,
                repo_id,
                int(sender["id"]),
                "ignored",
                reason or "no reason given",
            ):
                await store.bump_rule_stat(db, row.rule_id or "", "not_useful")
    for row in rows:
        if row.comment_id:
            await svc.github.update_review_comment(
                repo.installation_id,
                repo.full_name or "",
                row.comment_id,
                f"🙈 Dismissed by @{sender['login']}: {reason or 'no reason given'}",
            )
    return f"dismissed {len(rows)} finding(s)"


HANDLERS = {
    "installation": on_installation,
    "installation_repositories": on_installation_repositories,
    "pull_request": on_pull_request,
    "push": on_push,
    "check_run": on_check_run,
    "issue_comment": on_issue_comment,
}
