"""Publish findings to GitHub (REP): inline comments upserted by fingerprint, fixed findings
resolved, check-run summary. Delivery only: findings come from authgraph unchanged except for
display tier (auto-demotion of rules over 10% effective FP, PLAN.md §2 FB)."""

from __future__ import annotations

import logging
import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import date, timedelta

from authgraph.facts.models import Finding

from accessguard_app import metrics
from accessguard_app.db.models import FindingRow
from accessguard_app.domain import store
from accessguard_app.github.port import CommentOutsideDiff, GitHubPort
from accessguard_app.reporter import render
from accessguard_app.runtime import Services

log = logging.getLogger("accessguard.reporter")
SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}
DEMOTE_RATE = 0.10
DEMOTE_MIN_SHOWN = 20


@dataclass
class PublishResult:
    posted: int
    updated: int
    resolved: int
    summary_only: int
    conclusion: str
    title: str
    summary: str


def fails_check(f: Finding, fail_on: str) -> bool:
    if fail_on == "never" or f.tier != "deterministic":
        return False
    return SEVERITY_RANK[f.severity] <= SEVERITY_RANK[fail_on]


async def demoted_rules(svc: Services, rule_ids: set[str]) -> set[str]:
    out = set()
    async with svc.sessions() as db:
        for rid in rule_ids:
            shown, bad = await store.rule_effective_fp(db, rid, date.today() - timedelta(days=90))
            if shown >= DEMOTE_MIN_SHOWN and bad / shown > DEMOTE_RATE:
                out.add(rid)
    return out


async def publish_pr(
    svc: Services,
    *,
    installation_id: int,
    repo: str,
    repo_id: int,
    pr: int,
    head_sha: str,
    scan_id: uuid.UUID,
    findings: Sequence[Finding],
    fail_on: str,
    endpoints: int,
    unknown: int,
    suppressed: int = 0,
) -> PublishResult:
    gh: GitHubPort = svc.github
    demoted = await demoted_rules(svc, {f.rule_id for f in findings})
    shown = [
        f.model_copy(update={"tier": "advisory"}) if f.rule_id in demoted else f for f in findings
    ]
    async with svc.sessions() as db:
        existing = await store.open_findings(db, repo_id, pr)
        dismissed = await store.dismissed_fingerprints(db, repo_id, pr)
        intro = not await store.repo_has_reported(db, repo_id)
    shown = [f for f in shown if f.fingerprint not in dismissed]
    posted = updated = summary_only = 0
    current = {f.fingerprint for f in shown}
    for f in shown:
        row = existing.get(f.fingerprint)
        body = render.comment_body(f)
        comment_id = row.comment_id if row else None
        if f.tier == "deterministic":
            if comment_id:
                await gh.update_review_comment(installation_id, repo, comment_id, body)
                updated += 1
            else:
                try:
                    comment_id = await gh.create_review_comment(
                        installation_id,
                        repo,
                        pr,
                        {
                            "body": body,
                            "commit_id": head_sha,
                            "path": f.loc.path,
                            "line": max(f.loc.line, 1),
                            "side": "RIGHT",
                        },
                    )
                    posted += 1
                    metrics.FINDINGS.labels(rule_id=f.rule_id, tier=f.tier).inc()
                except CommentOutsideDiff:
                    log.info(
                        "inline comment rejected; summary only",
                        extra={"fingerprint": f.fingerprint},
                    )
                    summary_only += 1
        if row is None:
            async with svc.sessions() as db:
                await store.bump_rule_stat(db, f.rule_id, "shown")
        async with svc.sessions() as db:
            await store.save_finding(
                db,
                FindingRow(
                    finding_id=row.finding_id if row else uuid.uuid4(),
                    scan_id=scan_id,
                    repo_id=repo_id,
                    pr_number=pr,
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
                    comment_id=comment_id,
                    first_seen_sha=row.first_seen_sha if row else head_sha,
                    last_seen_sha=head_sha,
                ),
            )
    resolved = 0
    for fp, row in existing.items():
        if fp in current:
            continue
        resolved += 1
        if row.comment_id:
            await gh.update_review_comment(
                installation_id,
                repo,
                row.comment_id,
                render.resolved_body(render.comment_body_from_row(row), head_sha),
            )
        row.status = "resolved"
        row.last_seen_sha = head_sha
        async with svc.sessions() as db:
            await store.save_finding(db, row)
            await store.bump_rule_stat(db, row.rule_id or "", "acted")
    failing = [f for f in shown if fails_check(f, fail_on)]
    title, text = render.summary(
        shown,
        resolved=resolved,
        unknown=unknown,
        endpoints=endpoints,
        intro=intro,
        demoted=sorted(demoted),
        suppressed=suppressed,
    )
    return PublishResult(
        posted, updated, resolved, summary_only, "failure" if failing else "success", title, text
    )
