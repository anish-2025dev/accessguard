from __future__ import annotations

import io
import json
import tarfile
import uuid
from pathlib import Path
from typing import Any

import httpx
from accessguard_app.api.main import create_app, pkce_pair, verify_signature
from accessguard_app.db.models import Feedback, FindingRow, Repository, WebhookDelivery
from accessguard_app.fetch import safe_extract
from accessguard_app.jobs import reconcile
from accessguard_app.runtime import Services
from githubkit.webhooks import sign
from sqlalchemy import func, select

from .conftest import WEBHOOK_SECRET, ctx, drain
from .fakes import FakeGitHub, InMemoryQueue

MUTATIONS = Path(__file__).resolve().parents[3] / "eval" / "mutations"
REPO, REPO_ID, INST = "acme/api", 42, 7


# --- HMAC (GitHub's published test vector) -----------------------------------------------------


def test_github_hmac_test_vector() -> None:
    # https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries
    sig = "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17"
    assert verify_signature("It's a Secret to Everybody", b"Hello, World!", sig)
    assert not verify_signature("It's a Secret to Everybody", b"Hello, World!!", sig)
    sha1 = sign("It's a Secret to Everybody", b"Hello, World!", "sha1")
    assert not verify_signature("It's a Secret to Everybody", b"Hello, World!", sha1)


def test_pkce_s256() -> None:
    import base64
    import hashlib

    verifier, challenge = pkce_pair()
    digest = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=")
    assert challenge == digest.decode() and len(challenge) == 43


def test_safe_extract_drops_links_and_traversal(tmp_path: Path) -> None:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for name, data in (("top/ok.py", b"x=1"), ("top/../../evil.py", b"bad")):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        link = tarfile.TarInfo("top/link.py")
        link.type = tarfile.SYMTYPE
        link.linkname = "/etc/passwd"
        tar.addfile(link)
    safe_extract(buf.getvalue(), tmp_path, 10_000)
    assert sorted(p.name for p in tmp_path.rglob("*") if p.is_file()) == ["ok.py"]


# --- helpers ---------------------------------------------------------------------------------


async def post_event(
    svc: Services,
    event: str,
    payload: dict[str, Any],
    guid: str | None = None,
    secret: str = WEBHOOK_SECRET,
) -> httpx.Response:
    body = json.dumps(payload).encode()
    app = create_app(svc)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        return await c.post(
            "/webhooks/github",
            content=body,
            headers={
                "x-hub-signature-256": sign(secret, body, "sha256"),
                "x-github-delivery": guid or str(uuid.uuid4()),
                "x-github-event": event,
                "content-type": "application/json",
            },
        )


def gh(svc: Services) -> FakeGitHub:
    assert isinstance(svc.github, FakeGitHub)
    return svc.github


def setup_repo(svc: Services, case: str) -> tuple[str, str]:
    """Repo whose base/head commits are an eval mutation case's base and head trees."""
    g = gh(svc)
    r = g.add_repo(INST, REPO, REPO_ID)
    base, head = f"b{case[:6]}".ljust(40, "0"), f"h{case[:6]}".ljust(40, "0")
    r.commits[base] = MUTATIONS / case / "base"
    r.commits[head] = MUTATIONS / case / "head"
    r.permissions.update({"maint": "write", "reader": "read"})
    return base, head


def pr_payload(action: str, number: int = 1) -> dict[str, Any]:
    return {
        "action": action,
        "installation": {"id": INST},
        "repository": {"id": REPO_ID, "full_name": REPO, "default_branch": "main"},
        "pull_request": {"number": number},
    }


async def install(svc: Services) -> None:
    g = gh(svc)
    r = await post_event(
        svc, "installation", {"action": "created", "installation": g.installations[INST]}
    )
    assert r.status_code == 202
    await drain(svc, include={"route_delivery"})
    gh(svc)  # baselines queued on the low queue are drained by tests that need them


# --- intake and outbox -----------------------------------------------------------------------


async def test_intake_verifies_stores_dedups_and_survives_queue_outage(services: Services) -> None:
    guid = str(uuid.uuid4())
    r = await post_event(services, "ping", {"zen": "hi"}, guid=guid)
    assert r.status_code == 202
    r = await post_event(services, "ping", {"zen": "hi"}, guid=guid)
    assert (r.status_code, r.json()["status"]) == (200, "duplicate")
    r = await post_event(services, "ping", {"zen": "hi"}, secret="wrong")
    assert r.status_code == 401
    q = services.queue
    assert isinstance(q, InMemoryQueue)
    assert [j.job_id for j in q.jobs] == [f"delivery:{guid}"]
    # Redis down: the delivery is still accepted and stays in the outbox...
    q.fail = True
    lost = str(uuid.uuid4())
    assert (await post_event(services, "ping", {"zen": "x"}, guid=lost)).status_code == 202
    q.fail = False
    async with services.sessions() as db:
        await db.execute(
            WebhookDelivery.__table__.update()
            .where(WebhookDelivery.delivery_guid == uuid.UUID(lost))
            .values(received_at=func.now() - func.make_interval(0, 0, 0, 0, 0, 5))
        )
        await db.commit()
    # ...until the sweeper re-enqueues it.
    assert await reconcile.outbox_sweeper(ctx(services)) == 1
    assert f"delivery:{lost}" in {j.job_id for j in q.jobs}


# --- end-to-end PR flow ------------------------------------------------------------------------


async def test_pr_scan_reports_then_resolves(services: Services) -> None:
    base, head = setup_repo(services, "m03_drop_depends")
    await install(services)
    async with services.sessions() as db:
        assert (await db.get(Repository, REPO_ID)).status == "active"  # type: ignore[union-attr]
    g = gh(services)
    g.set_pull(REPO, 1, base, head)
    await post_event(services, "pull_request", pr_payload("opened"))
    results = await drain(services, include={"route_delivery", "scan_pr"})
    assert ("scan_pr", "failure") in results
    (check,) = g.check_runs.values()
    assert check["conclusion"] == "failure" and check["head_sha"] == head
    assert (
        "AG-AUTH-002" in check["output"]["summary"] and "AccessGuard" in check["output"]["summary"]
    )
    (comment,) = g.review_comments.values()
    assert comment["path"] == "app/routers/admin.py" and "AG-AUTH-002" in comment["body"]
    # The author restores the guard: same fingerprint is resolved, comment updated in place.
    fixed = "f".ljust(40, "0")
    g.repos[REPO].commits[fixed] = MUTATIONS / "m03_drop_depends" / "base"
    g.set_pull(REPO, 1, base, fixed)
    await post_event(services, "pull_request", pr_payload("synchronize"))
    results = await drain(services, include={"route_delivery", "scan_pr"})
    assert ("scan_pr", "success") in results
    assert len(g.review_comments) == 1
    assert next(iter(g.review_comments.values()))["body"].startswith("✅ Resolved in f000000")
    async with services.sessions() as db:
        statuses = (await db.execute(select(FindingRow.status))).scalars().all()
    assert statuses == ["resolved"]


async def test_newer_push_supersedes_running_scan(services: Services) -> None:
    base, head = setup_repo(services, "m01_new_unauth_mutating_route")
    await install(services)
    g = gh(services)
    g.set_pull(REPO, 1, base, head)
    await post_event(services, "pull_request", pr_payload("opened"))
    await drain(services, include={"route_delivery"})
    first = gh(services)  # first scan job is queued; a new push arrives before it runs
    newer = "n".ljust(40, "0")
    g.repos[REPO].commits[newer] = MUTATIONS / "m01_new_unauth_mutating_route" / "head"
    g.set_pull(REPO, 1, base, newer)
    await post_event(services, "pull_request", pr_payload("synchronize"))
    results = await drain(services, include={"route_delivery", "scan_pr"})
    outcomes = [r for f, r in results if f == "scan_pr"]
    assert "skipped: head moved or PR closed" in outcomes or "superseded" in outcomes
    assert [c["head_sha"] for c in first.check_runs.values()] == [newer]


async def test_drafts_skipped_until_ready(services: Services) -> None:
    base, head = setup_repo(services, "m01_new_unauth_mutating_route")
    await install(services)
    g = gh(services)
    g.set_pull(REPO, 1, base, head, draft=True)
    await post_event(services, "pull_request", pr_payload("opened"))
    assert ("route_delivery", "draft skipped") in await drain(services, include={"route_delivery"})
    g.set_pull(REPO, 1, base, head, draft=False)
    await post_event(services, "pull_request", pr_payload("ready_for_review"))
    results = await drain(services, include={"route_delivery", "scan_pr"})
    assert ("scan_pr", "failure") in results


async def test_commands_permissions_bot_guard_and_ignore(services: Services) -> None:
    base, head = setup_repo(services, "m03_drop_depends")
    await install(services)
    g = gh(services)
    g.set_pull(REPO, 1, base, head)
    await post_event(services, "pull_request", pr_payload("opened"))
    await drain(services, include={"route_delivery", "scan_pr"})

    def comment(body: str, login: str, user_type: str = "User") -> dict[str, Any]:
        return {
            "action": "created",
            "installation": {"id": INST},
            "repository": {"id": REPO_ID, "full_name": REPO},
            "issue": {"number": 1, "pull_request": {}},
            "comment": {"body": body},
            "sender": {"login": login, "id": hash(login) % 10**6, "type": user_type},
        }

    await post_event(services, "issue_comment", comment("@accessguard scan", "reader"))
    await post_event(
        services, "issue_comment", comment("@accessguard scan", "accessguard[bot]", "Bot")
    )
    out = [r for _, r in await drain(services, include={"route_delivery"})]
    assert out == ["commenter lacks write permission", "bot comment ignored"]
    async with services.sessions() as db:
        fp = (await db.execute(select(FindingRow.fingerprint))).scalar_one()
    await post_event(
        services,
        "issue_comment",
        comment(f"@accessguard ignore {fp[:10]} intended for admins", "maint"),
    )
    assert [r for _, r in await drain(services, include={"route_delivery"})] == [
        "dismissed 1 finding(s)"
    ]
    async with services.sessions() as db:
        assert (await db.execute(select(FindingRow.status))).scalar_one() == "dismissed"
        assert (await db.execute(select(Feedback.kind))).scalar_one() == "ignored"
    await post_event(services, "issue_comment", comment("@accessguard scan", "maint"))
    results = await drain(services, include={"route_delivery", "scan_pr"})
    assert results[0][1].startswith("scan scheduled")


async def test_push_to_main_creates_one_deduplicated_issue(services: Services) -> None:
    base, head = setup_repo(services, "m03_drop_depends")
    await install(services)
    push = {
        "ref": "refs/heads/main",
        "before": base,
        "after": head,
        "installation": {"id": INST},
        "repository": {"id": REPO_ID, "full_name": REPO, "default_branch": "main"},
    }
    await post_event(services, "push", push)
    await post_event(services, "push", push)  # same push redelivered with a new GUID
    await drain(services, include={"route_delivery", "scan_push"})
    g = gh(services)
    assert len(g.issues) == 1 and "AG-AUTH-002" in g.issues[0]["body"]
    assert [c["conclusion"] for c in g.check_runs.values()] == ["failure"]


async def test_installation_lifecycle_and_state_reconcile(services: Services) -> None:
    setup_repo(services, "m01_new_unauth_mutating_route")
    await install(services)
    q = services.queue
    assert isinstance(q, InMemoryQueue)
    assert [j.function for j in q.jobs] == ["baseline_scan"]  # FR-1.6, low queue, no writes
    assert q.jobs[0].queue == "low"
    g = gh(services)
    g.repos[REPO].commits["main"] = MUTATIONS / "m01_new_unauth_mutating_route" / "base"
    results = await drain(services, include={"baseline_scan"})
    assert results[0][1].startswith("baseline:") and not g.check_runs and not g.review_comments
    # Uninstalled while we were down: the hourly reconcile notices.
    g.installations.clear()
    await reconcile.reconcile_state(ctx(services))
    async with services.sessions() as db:
        assert (await db.get(Repository, REPO_ID)).status == "removed"  # type: ignore[union-attr]


async def test_server_down_loses_no_webhooks(services: Services) -> None:
    """While the API is down GitHub records failed deliveries; the reconciler redelivers the
    ones we never stored and they flow through the normal intake (PLAN.md §3 Phase 2 gate)."""
    base, head = setup_repo(services, "m01_new_unauth_mutating_route")
    await install(services)
    g = gh(services)
    g.set_pull(REPO, 1, base, head)
    missed = {
        101: (str(uuid.uuid4()), pr_payload("opened")),
        102: (str(uuid.uuid4()), {"zen": "ping"}),
    }
    g.failed_deliveries = [{"id": i, "guid": guid} for i, (guid, _) in missed.items()]
    received_already = str(uuid.uuid4())
    g.failed_deliveries.append({"id": 103, "guid": received_already})
    await post_event(services, "ping", {"zen": "later attempt arrived"}, guid=received_already)

    async def redeliver(delivery_id: int) -> None:
        guid, payload = missed[delivery_id]
        event = "pull_request" if "pull_request" in payload else "ping"
        await post_event(services, event, payload, guid=guid)

    g.redeliver_hook = redeliver
    assert await reconcile.reconcile_deliveries(ctx(services)) == 2
    assert sorted(g.redelivered) == [101, 102]
    results = await drain(services, include={"route_delivery", "scan_pr"})
    assert ("scan_pr", "failure") in results
    async with services.sessions() as db:
        n = await db.scalar(
            select(func.count())
            .select_from(WebhookDelivery)
            .where(WebhookDelivery.status != "routed")
        )
    assert n == 0


async def test_connect_and_callback_link_only_listed_installations(services: Services) -> None:
    setup_repo(services, "m01_new_unauth_mutating_route")
    g = gh(services)
    app = create_app(services)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        r = await c.get("/connect")
        assert r.status_code == 302
        q = dict(httpx.URL(r.headers["location"]).params)
        assert q["code_challenge_method"] == "S256" and len(q["code_challenge"]) == 43
        from accessguard_app.db.models import OAuthState

        async with services.sessions() as db:
            verifier = (await db.get(OAuthState, q["state"])).pkce_verifier  # type: ignore[union-attr]
        g.oauth_codes["c1"] = (verifier, 55)
        g.user_installations[55] = [INST]
        r = await c.get("/callback", params={"code": "c1", "state": q["state"]})
        assert r.status_code == 200 and "Linked 1 installation" in r.text
        # The state is single-use.
        g.oauth_codes["c2"] = (verifier, 55)
        r = await c.get("/callback", params={"code": "c2", "state": q["state"]})
        assert r.status_code == 400


async def test_push_during_scan_cancels_check_run(services: Services) -> None:
    from accessguard_app.runtime import bump_generation

    base, head = setup_repo(services, "m03_drop_depends")
    await install(services)
    g = gh(services)
    g.set_pull(REPO, 1, base, head)
    await post_event(services, "pull_request", pr_payload("opened"))
    await drain(services, include={"route_delivery"})
    real = g.download_tarball

    async def slow_fetch(inst: int, repo: str, ref: str) -> bytes:
        if ref == head:  # a newer push lands while we are fetching
            await bump_generation(services.redis, REPO_ID, 1, "z" * 40)
        return await real(inst, repo, ref)

    g.download_tarball = slow_fetch  # type: ignore[method-assign]
    results = await drain(services, include={"scan_pr"})
    assert results == [("scan_pr", "superseded")]
    (check,) = g.check_runs.values()
    assert check["conclusion"] == "cancelled" and not g.review_comments
