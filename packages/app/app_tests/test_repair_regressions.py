"""Regression coverage across the repaired delivery and persistence boundaries."""

import uuid
from datetime import UTC, datetime
from unittest.mock import AsyncMock

import pytest
from accessguard_app.db.models import FindingRow, Installation, Repository, Scan
from accessguard_app.domain import store
from accessguard_app.github.port import CommentOutsideDiff, InstallationGone, RateLimited
from accessguard_app.jobs import reconcile, router, scan
from accessguard_app.reporter.publish import publish_pr
from authgraph.api import diff_trees
from authgraph.guards.config import Config
from authgraph.workspace.tree import DirectoryTree
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from .conftest import ctx
from .fakes import InMemoryQueue
from .test_app_flow import INST, MUTATIONS, REPO, REPO_ID, gh, install, setup_repo


@pytest.mark.parametrize("pr", [1, None])
@pytest.mark.parametrize("base", ["base", None])
async def test_scan_identity_and_null_deduplication(services, pr, base) -> None:
    setup_repo(services, "m03_drop_depends")
    await install(services)
    identity = dict(
        repo_id=REPO_ID,
        pr_number=pr,
        trigger="pr" if pr else "baseline",
        base_sha=base,
        head_sha="head",
        config_hash="cfg",
        generation=1,
    )
    async with services.sessions() as db:
        first, created = await store.start_scan(db, **identity)
        assert created
        await store.finish_scan(db, first, "done")
        assert await store.start_scan(db, **identity) == (first, False)
        for change in ({"pr_number": 2}, {"base_sha": "other-base"}):
            other, created = await store.start_scan(db, **(identity | change))
            assert created and other != first
            await store.finish_scan(db, other, "done")
        # Enforce the same identity at the actual migrated DB boundary, including NULLs.
        db.add(Scan(scan_id=uuid.uuid4(), status="done", **identity))
        with pytest.raises(IntegrityError):
            await db.commit()
        await db.rollback()


@pytest.mark.parametrize("stamp", [None, "2026-10-23T12:30:00Z", "2026-10-23T14:30:00+02:00"])
async def test_installation_suspension_timestamp(services, stamp) -> None:
    setup_repo(services, "m03_drop_depends")
    inst = gh(services).installations[INST] | {"suspended_at": stamp}
    async with services.sessions() as db:
        await store.upsert_installation(db, inst)
        row = await db.get(Installation, INST)
        assert row.suspended_at == (datetime(2026, 10, 23, 12, 30, tzinfo=UTC) if stamp else None)
        await store.upsert_installation(db, inst | {"suspended_at": None})
        await db.refresh(row)
        assert row.suspended_at is None


async def test_ignore_prefix_matches_sql_wildcards_and_escape_literally(services) -> None:
    fingerprints = ["abc%_/literal", "abcXX/literal", "abc%_/other", "abcZZZ"]
    async with services.sessions() as db:
        for fp in fingerprints:
            await store.save_finding(
                db,
                FindingRow(
                    finding_id=uuid.uuid4(),
                    repo_id=REPO_ID,
                    pr_number=1,
                    fingerprint=fp,
                    status="open",
                ),
            )
        rows = await store.finding_by_fingerprint(db, REPO_ID, 1, "abc%_/")
        assert {r.fingerprint for r in rows} == {"abc%_/literal", "abc%_/other"}


async def test_reconcile_continues_after_failed_installation(services, monkeypatch, caplog) -> None:
    setup_repo(services, "m03_drop_depends")
    g = gh(services)
    g.add_repo(8, "acme/other", 43)
    g.add_repo(9, "acme/suspended", 44)
    g.installations[9]["suspended_at"] = "2026-10-23T12:30:00Z"
    real = g.list_installation_repos

    async def list_repos(iid):
        if iid == INST:
            raise RateLimited(5)
        return await real(iid)

    listed = AsyncMock(side_effect=list_repos)
    monkeypatch.setattr(g, "list_installation_repos", listed)
    assert await reconcile.reconcile_state(ctx(services)) == "3 installations, 0 removed"
    assert [c.args[0] for c in listed.call_args_list] == [INST, 8]
    assert any(
        r.installation_id == INST for r in caplog.records if r.message == "repository resync failed"
    )
    async with services.sessions() as db:
        assert (await db.get(Repository, 43)).status == "active"


async def test_same_head_generations_can_both_be_queued(services) -> None:
    base, head = setup_repo(services, "m03_drop_depends")
    await install(services)
    gh(services).set_pull(REPO, 1, base, head)
    for gen in (1, 2):
        assert (
            await router.schedule_pr_scan(services, REPO_ID, 1, force=False)
            == f"scan scheduled g{gen}"
        )
    q = services.queue
    assert isinstance(q, InMemoryQueue)
    jobs = [j for j in q.jobs if j.function == "scan_pr"]
    assert {j.job_id for j in jobs} == {
        f"scan:{REPO_ID}:1:{head}:g1",
        f"scan:{REPO_ID}:1:{head}:g2",
    }
    assert await scan.scan_pr(ctx(services), *jobs[-1].args) == "failure"


async def test_unauthorized_commands_do_not_consume_pr_budget(services, monkeypatch) -> None:
    monkeypatch.setattr("accessguard_app.runtime.time.time", lambda: 1000)
    base, head = setup_repo(services, "m03_drop_depends")
    await install(services)
    g = gh(services)
    g.set_pull(REPO, 1, base, head)
    payload = {
        "repository": {"id": REPO_ID},
        "issue": {"number": 1, "pull_request": {}},
        "comment": {"body": "@accessguard scan"},
        "sender": {"id": 1, "login": "reader", "type": "User"},
    }
    for _ in range(30):
        assert (
            await router.on_issue_comment(services, "created", payload)
            == "commenter lacks write permission"
        )
    permission = AsyncMock(wraps=g.get_permission)
    monkeypatch.setattr(g, "get_permission", permission)
    assert await router.on_issue_comment(services, "created", payload) == "rate limited"
    permission.assert_not_awaited()
    payload["sender"] = {"id": 2, "login": "maint", "type": "User"}
    for _ in range(5):
        assert (await router.on_issue_comment(services, "created", payload)).startswith(
            "scan scheduled"
        )
    assert await router.on_issue_comment(services, "created", payload) == "rate limited"
    assert await services.redis.get("cmd:user:2:0") == b"6"


@pytest.mark.parametrize("gone", [False, True])
@pytest.mark.parametrize("update_fails", [False, True])
async def test_scan_completes_check_on_provider_failure(
    services, monkeypatch, gone, update_fails
) -> None:
    base, head = setup_repo(services, "m03_drop_depends")
    await install(services)
    g = gh(services)
    g.set_pull(REPO, 1, base, head)
    await router.schedule_pr_scan(services, REPO_ID, 1, force=False)
    error = InstallationGone() if gone else RateLimited(37)
    monkeypatch.setattr(scan, "run_diff", AsyncMock(side_effect=error))
    update = (
        AsyncMock(side_effect=RuntimeError("cannot update"))
        if update_fails
        else AsyncMock(wraps=g.update_check_run)
    )
    monkeypatch.setattr(g, "update_check_run", update)
    if gone:
        assert (
            await scan.scan_pr(ctx(services), REPO_ID, 1, head, 1)
            == "failed: installation no longer accessible"
        )
    else:
        with pytest.raises(RateLimited) as raised:
            await scan.scan_pr(ctx(services), REPO_ID, 1, head, 1)
        assert raised.value is error
    assert update.await_args.args[-1] == {
        "status": "completed",
        "conclusion": "failure" if gone else "neutral",
    }
    if not update_fails:
        (check,) = g.check_runs.values()
        assert check["status"] == "completed"
    async with services.sessions() as db:
        row = (await db.execute(select(Scan))).scalar_one()
        assert row.status == "failed" and row.check_run_id is not None
        assert (await db.get(Repository, REPO_ID)).status == ("paused" if gone else "active")


def mutation_result():
    case = MUTATIONS / "m03_drop_depends"
    return diff_trees(
        DirectoryTree(case / "base"), DirectoryTree(case / "head"), repo_id=str(REPO_ID)
    )


@pytest.mark.parametrize(
    ("fail_on", "tier", "severity", "conclusion"),
    [
        ("critical", "deterministic", "high", "success"),
        ("high", "deterministic", "high", "failure"),
        ("critical", "deterministic", "critical", "failure"),
        ("never", "deterministic", "critical", "success"),
        ("high", "advisory", "critical", "success"),
    ],
)
async def test_push_check_uses_configured_threshold(
    services, monkeypatch, fail_on, tier, severity, conclusion
) -> None:
    base, head = setup_repo(services, "m03_drop_depends")
    await install(services)
    result = mutation_result()
    result.findings = [
        f.model_copy(update={"tier": tier, "severity": severity}) for f in result.findings
    ]
    assert result.findings
    monkeypatch.setattr(scan, "run_diff", AsyncMock(return_value=result))
    monkeypatch.setattr(
        scan, "load_base_config", AsyncMock(return_value=(Config(fail_on=fail_on), "cfg"))
    )
    await scan.scan_push(ctx(services), REPO_ID, base, head)
    assert [c["conclusion"] for c in gh(services).check_runs.values()] == [conclusion]


async def publish(services, findings, pr=1):
    return await publish_pr(
        services,
        installation_id=INST,
        repo=REPO,
        repo_id=REPO_ID,
        pr=pr,
        head_sha="head",
        scan_id=None,
        findings=findings,
        fail_on="high",
        endpoints=1,
        unknown=0,
    )


async def test_dismissed_finding_stays_dismissed_and_does_not_fail(services) -> None:
    findings = mutation_result().findings
    first = await publish(services, findings)
    assert first.conclusion == "failure"
    async with services.sessions() as db:
        row = (await db.execute(select(FindingRow))).scalar_one()
        row.status = "dismissed"
        await store.save_finding(db, row)
    again = await publish(services, findings)
    assert (again.posted, again.updated, again.conclusion) == (0, 0, "success")
    async with services.sessions() as db:
        assert (await db.execute(select(FindingRow.status))).scalars().all() == ["dismissed"]
    # Dismissal remains scoped to this repository and PR.
    other = await publish(services, findings, pr=2)
    assert other.posted == 1 and other.conclusion == "failure"


@pytest.mark.parametrize(
    "error",
    [CommentOutsideDiff(), RateLimited(5), ConnectionError("offline"), RuntimeError("unexpected")],
)
async def test_reporter_only_swallows_outside_diff_rejection(services, monkeypatch, error) -> None:
    monkeypatch.setattr(gh(services), "create_review_comment", AsyncMock(side_effect=error))
    findings = mutation_result().findings
    if isinstance(error, CommentOutsideDiff):
        result = await publish(services, findings)
        assert result.summary_only == 1 and result.conclusion == "failure"
    else:
        with pytest.raises(type(error)) as raised:
            await publish(services, findings)
        assert raised.value is error
        async with services.sessions() as db:
            assert (await db.execute(select(FindingRow))).scalars().all() == []
