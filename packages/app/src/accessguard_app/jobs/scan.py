"""``scan_pr``, ``scan_push``, ``baseline_scan`` (PLAN.md §6.8, §6.12).

The worker fetches both commits as tarballs, runs ``authgraph`` on them in a thread (parsing
only, ADR 005), and hands the findings to the reporter. The PR generation is checked between
phases; a newer head raises ``Superseded`` and the check run is cancelled.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import time
import uuid
from dataclasses import dataclass
from typing import Any

from authgraph.api import DiffResult, diff_trees
from authgraph.cache.summaries import MemoryCache, SummaryCache
from authgraph.engine import analyze
from authgraph.guards.config import CONFIG_FILE, Config, parse_config
from authgraph.workspace.tree import DirectoryTree

from accessguard_app import metrics
from accessguard_app.db.models import FindingRow
from accessguard_app.domain import stack, store
from accessguard_app.fetch import checkout
from accessguard_app.github.port import InstallationGone, RateLimited
from accessguard_app.reporter.publish import publish_pr
from accessguard_app.reporter.render import ICON
from accessguard_app.runtime import RedisSummaryCache, Services, current_generation, take_token

log = logging.getLogger("accessguard.scan")


class Superseded(Exception):
    pass


@dataclass
class RepoRef:
    repo_id: int
    full_name: str
    installation_id: int
    default_branch: str


async def _repo(svc: Services, repo_id: int) -> RepoRef | None:
    async with svc.sessions() as db:
        r = await store.get_repo(db, repo_id)
    if r is None or r.status != "active" or r.installation_id is None or not r.full_name:
        return None
    return RepoRef(repo_id, r.full_name, r.installation_id, r.default_branch or "main")


def _cache(svc: Services) -> SummaryCache:
    return RedisSummaryCache(svc.sync_redis) if svc.sync_redis is not None else MemoryCache()


async def load_base_config(svc: Services, ref: RepoRef, base_sha: str) -> tuple[Config, str]:
    """``.accessguard.yml`` from the BASE commit only (ADR 006)."""
    raw = await svc.github.get_file(ref.installation_id, ref.full_name, CONFIG_FILE, base_sha)
    return parse_config(raw), hashlib.sha256(raw or b"").hexdigest()[:16]


async def run_diff(
    svc: Services,
    ref: RepoRef,
    base_sha: str,
    head_sha: str,
    cfg: Config,
    timings: dict[str, float],
) -> DiffResult:
    t = time.perf_counter()
    base_tar, head_tar = await asyncio.gather(
        svc.github.download_tarball(ref.installation_id, ref.full_name, base_sha),
        svc.github.download_tarball(ref.installation_id, ref.full_name, head_sha),
    )
    timings["fetch"] = time.perf_counter() - t
    metrics.SCAN_PHASE.labels(phase="fetch").observe(timings["fetch"])
    cap = svc.settings.max_tarball_bytes
    with checkout(base_tar, cap) as b, checkout(head_tar, cap) as h:
        t = time.perf_counter()
        result = await asyncio.to_thread(
            diff_trees,
            DirectoryTree(b, commit_sha=base_sha, exclude=cfg.paths.exclude),
            DirectoryTree(h, commit_sha=head_sha, exclude=cfg.paths.exclude),
            str(ref.repo_id),
            _cache(svc),
            cfg,
        )
        timings["analyze"] = time.perf_counter() - t
        metrics.SCAN_PHASE.labels(phase="analyze").observe(timings["analyze"])
    return result


async def _check_generation(svc: Services, repo_id: int, pr: int, gen: int) -> None:
    if await current_generation(svc.redis, repo_id, pr) != gen:
        raise Superseded()


async def scan_pr(ctx: dict[str, Any], repo_id: int, pr: int, head_sha: str, gen: int) -> str:
    svc: Services = ctx["services"]
    ref = await _repo(svc, repo_id)
    if ref is None:
        return "skipped: repository inactive"
    await _check_generation(svc, repo_id, pr, gen)
    live = await svc.github.get_pull(ref.installation_id, ref.full_name, pr)
    if live["head"]["sha"] != head_sha or live.get("state") != "open":
        return "skipped: head moved or PR closed"  # a newer job owns the new head
    base_sha = live["base"]["sha"]
    cfg, cfg_hash = await load_base_config(svc, ref, base_sha)
    async with svc.sessions() as db:
        scan_id, created = await store.start_scan(
            db,
            repo_id=repo_id,
            pr_number=pr,
            trigger="pr",
            base_sha=base_sha,
            head_sha=head_sha,
            config_hash=cfg_hash,
            generation=gen,
        )
    if not created:
        return "skipped: identical scan already done"
    check_id = await svc.github.create_check_run(
        ref.installation_id,
        ref.full_name,
        {
            "name": svc.settings.check_name,
            "head_sha": head_sha,
            "status": "in_progress",
            "external_id": str(scan_id),
        },
    )
    timings: dict[str, float] = {}
    t0 = time.perf_counter()
    try:
        await read_feedback(svc, ref, pr)
        result = await run_diff(svc, ref, base_sha, head_sha, cfg, timings)
        await _check_generation(svc, repo_id, pr, gen)
        cov = result.head.coverage
        metrics.UNKNOWN_RATE.observe(cov.unknown_rate)
        t = time.perf_counter()
        pub = await publish_pr(
            svc,
            installation_id=ref.installation_id,
            repo=ref.full_name,
            repo_id=repo_id,
            pr=pr,
            head_sha=head_sha,
            scan_id=scan_id,
            findings=result.findings,
            fail_on=cfg.fail_on,
            endpoints=cov.endpoints,
            unknown=cov.unknown,
        )
        timings["report"] = time.perf_counter() - t
        await _check_generation(svc, repo_id, pr, gen)
        await svc.github.update_check_run(
            ref.installation_id,
            ref.full_name,
            check_id,
            {
                "status": "completed",
                "conclusion": pub.conclusion,
                "output": {"title": pub.title, "summary": pub.summary},
            },
        )
        timings["total"] = time.perf_counter() - t0
        async with svc.sessions() as db:
            await store.finish_scan(
                db,
                scan_id,
                "done",
                check_run_id=check_id,
                coverage=cov.model_dump(mode="json"),
                timings=timings,
            )
        metrics.SCANS.labels(trigger="pr", outcome=pub.conclusion).inc()
        return pub.conclusion
    except Superseded:
        metrics.SUPERSEDED.inc()
        await svc.github.update_check_run(
            ref.installation_id,
            ref.full_name,
            check_id,
            {
                "status": "completed",
                "conclusion": "cancelled",
                "output": {
                    "title": "Superseded by a newer commit",
                    "summary": "A newer push to this pull request is being scanned.",
                },
            },
        )
        async with svc.sessions() as db:
            await store.finish_scan(db, scan_id, "superseded", check_run_id=check_id)
        return "superseded"
    except InstallationGone:
        async with svc.sessions() as db:
            await store.set_repo_fields(db, repo_id, status="paused")
            await store.finish_scan(db, scan_id, "failed", check_run_id=check_id)
        return "failed: installation no longer accessible"
    except RateLimited:
        metrics.RATE_LIMITED.inc()
        async with svc.sessions() as db:
            await store.finish_scan(db, scan_id, "failed", check_run_id=check_id)
        raise  # the worker retries with the server's retry-after (jobs.worker)
    except Exception:
        log.exception(
            "scan failed", extra={"scan_id": str(scan_id), "repo_id": repo_id, "head_sha": head_sha}
        )
        await svc.github.update_check_run(
            ref.installation_id,
            ref.full_name,
            check_id,
            {
                "status": "completed",
                "conclusion": "neutral",
                "output": {
                    "title": "AccessGuard could not complete this scan",
                    "summary": "The scan failed; no findings were reported. It will run "
                    "again on the next push or `@accessguard scan`.",
                },
            },
        )
        async with svc.sessions() as db:
            await store.finish_scan(db, scan_id, "failed", check_run_id=check_id)
        raise


async def scan_push(ctx: dict[str, Any], repo_id: int, before: str, after: str) -> str:
    """Push to the default branch (FR-2.2): diff ``before...after``, check run on ``after``, one
    deduplicated issue listing new high/critical findings."""
    svc: Services = ctx["services"]
    ref = await _repo(svc, repo_id)
    if ref is None:
        return "skipped: repository inactive"
    cfg, cfg_hash = await load_base_config(svc, ref, before)
    async with svc.sessions() as db:
        scan_id, created = await store.start_scan(
            db,
            repo_id=repo_id,
            pr_number=None,
            trigger="push",
            base_sha=before,
            head_sha=after,
            config_hash=cfg_hash,
            generation=None,
        )
    if not created:
        return "skipped: identical scan already done"
    timings: dict[str, float] = {}
    result = await run_diff(svc, ref, before, after, cfg, timings)
    async with svc.sessions() as db:
        seen = await store.open_findings(db, repo_id, None)
    new_high = [
        f
        for f in result.findings
        if f.severity in ("critical", "high") and f.fingerprint not in seen
    ]
    issue = None
    if new_high:
        body = "\n".join(
            f"- {ICON[f.severity]} `{f.rule_id}` {f.title} (`{f.loc.path}:{f.loc.line}`)"
            for f in new_high
        )
        issue = await svc.github.create_issue(
            ref.installation_id,
            ref.full_name,
            f"AccessGuard: {len(new_high)} access-control regression(s) in {after[:7]}",
            f"Introduced by `{before[:7]}...{after[:7]}`:\n\n{body}",
        )
    async with svc.sessions() as db:
        for f in result.findings:
            if f.fingerprint in seen:
                continue
            await store.save_finding(
                db,
                FindingRow(
                    finding_id=uuid.uuid4(),
                    scan_id=scan_id,
                    repo_id=repo_id,
                    pr_number=None,
                    fingerprint=f.fingerprint,
                    rule_id=f.rule_id,
                    severity=f.severity,
                    tier=f.tier,
                    status="open",
                    endpoint_id=f.endpoint_id or f.resource,
                    path=f.loc.path,
                    line=f.loc.line,
                    evidence=[s.model_dump(mode="json") for s in f.evidence],
                    llm_triage=None,
                    comment_id=issue,
                    first_seen_sha=after,
                    last_seen_sha=after,
                ),
            )
    failing = [
        f
        for f in result.findings
        if f.tier == "deterministic" and f.severity in ("critical", "high")
    ]
    check_id = await svc.github.create_check_run(
        ref.installation_id,
        ref.full_name,
        {
            "name": svc.settings.check_name,
            "head_sha": after,
            "status": "completed",
            "conclusion": "failure" if failing and cfg.fail_on != "never" else "success",
            "output": {
                "title": f"{len(result.findings)} finding(s) in this push",
                "summary": f"Compared `{before[:7]}...{after[:7]}`.",
            },
        },
    )
    async with svc.sessions() as db:
        await store.finish_scan(
            db,
            scan_id,
            "done",
            check_run_id=check_id,
            timings=timings,
            coverage=result.head.coverage.model_dump(mode="json"),
        )
    metrics.SCANS.labels(trigger="push", outcome="done").inc()
    return f"done: {len(result.findings)} finding(s)"


async def baseline_scan(ctx: dict[str, Any], repo_id: int, sha: str) -> str:
    """First scan after install (FR-1.6): no GitHub writes (FR-1.4), records stack and coverage."""
    svc: Services = ctx["services"]
    ref = await _repo(svc, repo_id)
    if ref is None:
        return "skipped"
    # Per-installation budget so one large org's baselines can't starve others (PLAN.md §5).
    if not await take_token(svc.redis, f"rl:inst:{ref.installation_id}:baseline", 10, 60):
        raise RateLimited(30)
    langs = await svc.github.list_languages(ref.installation_id, ref.full_name)
    tree = await svc.github.get_tree(ref.installation_id, ref.full_name, sha)
    detected = stack.detect(langs, [e["path"] for e in tree if e.get("type") == "blob"])
    data = await svc.github.download_tarball(ref.installation_id, ref.full_name, sha)
    with checkout(data, svc.settings.max_tarball_bytes) as root:
        facts = (
            await asyncio.to_thread(analyze, DirectoryTree(root, commit_sha=sha), None, _cache(svc))
        ).facts
    async with svc.sessions() as db:
        await store.set_repo_fields(db, repo_id, detected_stack=detected, last_baseline_sha=sha)
    return f"baseline: {facts.coverage.endpoints} endpoints"


async def read_feedback(svc: Services, ref: RepoRef, pr: int) -> None:
    """👎 reactions on our comments count as "not useful" (FB), read on later events."""
    async with svc.sessions() as db:
        rows = await store.open_findings(db, ref.repo_id, pr)
    for row in rows.values():
        if not row.comment_id:
            continue
        reacts = await svc.github.list_review_comment_reactions(
            ref.installation_id, ref.full_name, row.comment_id, "-1"
        )
        for r in reacts:
            async with svc.sessions() as db:
                if await store.add_feedback(
                    db, row.fingerprint, ref.repo_id, int(r["user"]["id"]), "not_useful", "👎"
                ):
                    await store.bump_rule_stat(db, row.rule_id or "", "not_useful")
