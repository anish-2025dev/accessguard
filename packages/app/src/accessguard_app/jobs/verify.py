"""``verify_findings`` (PLAN.md §6.8, queue ``arq:verify``): prove or refute a PR's open findings
against its preview deployment through the broker (FR-2.5, RV-1..4).

Runs only in the verifier worker, the one process holding the vault's private key. The job
re-checks the live PR head, reads ``verifier.enabled`` / ``preview_hosts`` from the base-branch
config, rebuilds the head facts (endpoints) from source, generates tools from the open findings,
runs the plans, records every broker call in ``verifier_audit``, marks verified findings with
tier ``verified`` and reports a separate ``<check> / runtime`` check run. It never runs code
from the repository and never sends anything but the generated calls to the preview host.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from typing import Any
from urllib.parse import urlsplit

from accessguard_verifier.broker import Broker
from accessguard_verifier.policy import Policy, host_allowed, system_resolver
from accessguard_verifier.tools import Identity, build_toolset
from accessguard_verifier.vault import Vault
from accessguard_verifier.verify import Result, verify
from authgraph.engine import analyze
from authgraph.facts.models import EvidenceStep, Finding, Loc
from authgraph.workspace.tree import DirectoryTree

from accessguard_app.domain import store
from accessguard_app.domain.verifier_store import DbAudit
from accessguard_app.fetch import checkout
from accessguard_app.jobs.scan import RepoRef, _repo, load_base_config
from accessguard_app.runtime import Services

log = logging.getLogger("accessguard.verify")
ICON = {"verified": "🔴", "refuted": "🟢", "inconclusive": "⚪"}


def _finding(row: Any) -> Finding:
    return Finding(
        rule_id=row.rule_id or "",
        fingerprint=row.fingerprint,
        severity=row.severity or "medium",
        tier=row.tier or "advisory",
        title=row.rule_id or "",
        endpoint_id=row.endpoint_id,
        loc=Loc(path=row.path or "", line=row.line or 0),
    )


async def verify_findings(
    ctx: dict[str, Any], repo_id: int, pr: int, scan_id: str, preview: str
) -> str:
    svc: Services = ctx["services"]
    vault: Vault | None = ctx.get("vault") or svc.extra.get("vault")
    if vault is None:
        return "skipped: verifier key not configured in this process"
    ref = await _repo(svc, repo_id)
    if ref is None:
        return "skipped: repository inactive"
    async with svc.sessions() as db:
        scan = await store.get_scan(db, uuid.UUID(scan_id))
    if scan is None or scan.status != "done" or scan.base_sha is None:
        return "skipped: scan not finished"
    live = await svc.github.get_pull(ref.installation_id, ref.full_name, pr)
    if live["head"]["sha"] != scan.head_sha or live.get("state") != "open":
        return "skipped: head moved or PR closed"
    cfg, _ = await load_base_config(svc, ref, scan.base_sha)
    host = urlsplit(preview).hostname or ""
    if not cfg.verifier.enabled:
        return "skipped: verifier.enabled is false on the base branch"
    if not host_allowed(host, cfg.verifier.preview_hosts):
        return "skipped: preview host is not in verifier.preview_hosts"
    async with svc.sessions() as db:
        rows = await store.open_findings(db, repo_id, pr)
    if not rows:
        return "nothing to verify"
    endpoints = await _head_endpoints(svc, ref, scan.head_sha)
    identities: tuple[Identity, ...] = ("anonymous",)
    have = {lab for lab in ("user_a", "user_b") if await vault.store.get(repo_id, lab)}
    identities += tuple(sorted(have))  # type: ignore[arg-type]
    findings = [_finding(r) for r in rows.values()]
    tools = build_toolset(findings, endpoints, identities)
    if not tools.targets:
        return "no verifiable findings"
    broker = Broker(
        repo_id=repo_id,
        scan_id=scan_id,
        base_url=f"https://{host}",
        tools=tools,
        policy=Policy(
            host,
            cfg.verifier.preview_hosts,
            budget=svc.settings.verifier_budget,
            resolver=svc.extra.get("resolver", system_resolver),
        ),
        vault=vault,
        audit=DbAudit(svc.sessions),
        transport=svc.extra.get("verifier_transport"),
    )
    results = await verify(tools, broker)
    await _record(svc, rows, results)
    await _report(svc, ref, scan.head_sha, results)
    counts = {
        d: sum(r.decision == d for r in results) for d in ("verified", "refuted", "inconclusive")
    }
    return ", ".join(f"{n} {d}" for d, n in counts.items())


async def _head_endpoints(svc: Services, ref: RepoRef, sha: str) -> list[Any]:
    tar = await svc.github.download_tarball(ref.installation_id, ref.full_name, sha)
    with checkout(tar, svc.settings.max_tarball_bytes) as root:
        analysis = await asyncio.to_thread(analyze, DirectoryTree(root, commit_sha=sha))
    return list(analysis.facts.endpoints)


async def _record(svc: Services, rows: dict[str, Any], results: list[Result]) -> None:
    for r in results:
        row = rows.get(r.fingerprint)
        if row is None:
            continue
        step = EvidenceStep(message=f"runtime check ({r.decision}): {r.reason}")
        row.evidence = [*(row.evidence or []), step.model_dump(mode="json")]
        if r.decision == "verified":
            row.tier = "verified"  # deterministic response comparison, never a model
        async with svc.sessions() as db:
            await store.save_finding(db, row)


def runtime_summary(results: list[Result]) -> tuple[str, str]:
    verified = [r for r in results if r.decision == "verified"]
    title = (
        f"{len(verified)} finding(s) verified against the preview"
        if verified
        else "No finding reproduced against the preview"
    )
    lines = [
        "Each flagged endpoint was called by the test identities through the AccessGuard "
        "broker; the outcome is decided by comparing responses, never by a model.\n",
        "| Result | Rule | Endpoint | Evidence |",
        "|---|---|---|---|",
    ]
    lines += [
        f"| {ICON[r.decision]} {r.decision} | `{r.rule_id}` | `{r.endpoint_id}` | {r.reason} |"
        for r in results
    ]
    return title, "\n".join(lines)


async def _report(svc: Services, ref: RepoRef, sha: str, results: list[Result]) -> None:
    title, summary = runtime_summary(results)
    await svc.github.create_check_run(
        ref.installation_id,
        ref.full_name,
        {
            "name": f"{svc.settings.check_name} / runtime",
            "head_sha": sha,
            "status": "completed",
            "conclusion": "failure"
            if any(r.decision == "verified" for r in results)
            else "success",
            "output": {"title": title, "summary": summary},
        },
    )
