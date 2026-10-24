"""Phase 4 end to end: credentials upload -> PR scan -> preview deployment -> runtime proof.

A PR adds ``GET /items/{item_id}`` that loads the user but does not tie it to the item
(AG-IDOR-002, advisory). A ``deployment_status``
webhook announces the preview; the verifier worker (the only holder of the vault's private key)
creates a fixture as user_a, reads it as user_b against an in-process preview with the IDOR
bug, and reports ``verified``. Secrets never reach the database in clear text, the audit log,
the check run or any API response.
"""

from __future__ import annotations

import json
import re
import textwrap
from pathlib import Path
from typing import Any

import httpx
from accessguard_app.api.main import create_app
from accessguard_app.db.models import FindingRow, VerifierAudit, VerifierCredential
from accessguard_app.domain.verifier_store import DbCredentialStore
from accessguard_app.runtime import Services
from accessguard_verifier.vault import Vault
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from sqlalchemy import select

from .conftest import drain
from .test_app_flow import INST, REPO, REPO_ID, gh, install, post_event, pr_payload

HOST = "acme-git-feature.vercel.app"
CONFIG = "version: 1\nverifier:\n  enabled: true\n  preview_hosts: ['*.vercel.app']\n"
DEPS = """
from fastapi import Depends, Header, HTTPException

def get_current_user(authorization: str = Header(...)):
    if not authorization:
        raise HTTPException(status_code=401)
    return {"id": 1}
"""
BASE_MAIN = """
from fastapi import Depends, FastAPI
from deps import get_current_user
from models import Item

app = FastAPI()

@app.post("/items")
def create(title: str, db=None, user=Depends(get_current_user)):
    return db.add(Item(title=title, owner_id=user["id"]))

@app.delete("/items/{item_id}")
def remove(item_id: int, db=None, user=Depends(get_current_user)):
    db.query(Item).filter(Item.id == item_id, Item.owner_id == user["id"]).delete()
"""
HEAD_MAIN = (
    BASE_MAIN
    + """
@app.get("/items/{item_id}")
def read(item_id: int, db=None, user=Depends(get_current_user)):
    return db.query(Item).filter(Item.id == item_id).first()
"""
)


def _tree(root: Path, main: str, config: bool) -> Path:
    root.mkdir(parents=True)
    (root / "deps.py").write_text(textwrap.dedent(DEPS))
    (root / "models.py").write_text("class Item: ...\n")
    (root / "main.py").write_text(textwrap.dedent(main))
    if config:
        (root / ".accessguard.yml").write_text(CONFIG)
    return root


class Preview:
    """The PR's preview deployment: bearer auth, but GET /items/{id} ignores the owner."""

    def __init__(self) -> None:
        self.items: dict[str, dict[str, Any]] = {}

    def __call__(self, request: httpx.Request) -> httpx.Response:
        user = {"Bearer ghp-test-a-123": "a", "Bearer ghp-test-b-456": "b"}.get(
            request.headers.get("authorization", "")
        )
        if user is None:
            return httpx.Response(401)
        m = re.fullmatch(r"/items/(\d+)", request.url.path)
        if request.method == "POST" and request.url.path == "/items":
            item_id = str(len(self.items) + 1)
            self.items[item_id] = {"owner": user, **json.loads(request.content)}
            return httpx.Response(201, json={"id": item_id})
        if m and m.group(1) in self.items:
            if request.method == "DELETE":
                if self.items[m.group(1)]["owner"] != user:
                    return httpx.Response(404)
                del self.items[m.group(1)]
                return httpx.Response(204)
            return httpx.Response(200, json={"id": m.group(1), **self.items[m.group(1)]})
        return httpx.Response(404)


async def _api(svc: Services, method: str, url: str, **kw: Any) -> httpx.Response:
    app = create_app(svc)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        return await c.request(method, url, **kw)


async def test_preview_deployment_verifies_idor(services: Services, tmp_path: Path) -> None:
    g = gh(services)
    r = g.add_repo(INST, REPO, REPO_ID)
    base, head = "b".ljust(40, "0"), "h".ljust(40, "0")
    r.commits[base] = _tree(tmp_path / "base", BASE_MAIN, config=True)
    r.commits[head] = _tree(tmp_path / "head", HEAD_MAIN, config=True)
    r.permissions.update({"user5": "write", "user6": "read"})
    vault = Vault(X25519PrivateKey.generate(), DbCredentialStore(services.sessions))
    preview = Preview()
    services.extra.update(
        sealer=vault.sealer(),  # the API process: public key only
        vault=vault,  # the verifier worker
        verifier_transport=httpx.MockTransport(preview),
        resolver=lambda host: ["76.76.21.21"],
    )
    await install(services)

    # Credentials: write access required, values never echoed.
    body = {
        "repo": REPO,
        "label": "user_a",
        "credential": {"type": "bearer", "token": "ghp-test-a-123"},
    }
    assert (await _api(services, "POST", "/verifier/credentials", json=body)).status_code == 401
    hdr = {"authorization": "Bearer ghu_6"}
    assert (
        await _api(services, "POST", "/verifier/credentials", json=body, headers=hdr)
    ).status_code == 403
    hdr = {"authorization": "Bearer ghu_5"}
    bad = await _api(
        services, "POST", "/verifier/credentials", json={**body, "label": "root"}, headers=hdr
    )
    assert bad.status_code == 422 and "ghp-test" not in bad.text
    assert (
        await _api(services, "POST", "/verifier/credentials", json=body, headers=hdr)
    ).status_code == 204
    body_b = {
        **body,
        "label": "user_b",
        "credential": {"type": "bearer", "token": "ghp-test-b-456"},
    }
    assert (
        await _api(services, "POST", "/verifier/credentials", json=body_b, headers=hdr)
    ).status_code == 204
    async with services.sessions() as db:
        rows = (await db.execute(select(VerifierCredential))).scalars().all()
    assert len(rows) == 2 and all(b"ghp-test" not in (x.ciphertext or b"") for x in rows)

    # The PR is scanned: AG-IDOR-002 (advisory: user loaded but not tied to the item).
    g.set_pull(REPO, 1, base, head)
    await post_event(services, "pull_request", pr_payload("opened"))
    await drain(services, include={"route_delivery", "scan_pr"})
    async with services.sessions() as db:
        found = (await db.execute(select(FindingRow))).scalars().all()
    assert {(f.rule_id, f.endpoint_id) for f in found} == {("AG-IDOR-002", "GET /items/{item_id}")}

    # The preview deployment succeeds.
    event = {
        "action": "created",
        "installation": {"id": INST},
        "repository": {"id": REPO_ID, "full_name": REPO},
        "deployment": {"sha": head, "environment": "Preview"},
        "deployment_status": {"state": "success", "environment_url": f"https://{HOST}"},
    }
    assert (await post_event(services, "deployment_status", event)).status_code == 202
    await drain(services, include={"route_delivery", "verify_findings"})

    runtime = [c for c in g.check_runs.values() if c["name"] == "AccessGuard / runtime"]
    assert len(runtime) == 1 and runtime[0]["head_sha"] == head
    assert runtime[0]["conclusion"] == "failure"
    assert "verified" in runtime[0]["output"]["summary"]
    async with services.sessions() as db:
        row = (await db.execute(select(FindingRow))).scalars().one()
        audit = (await db.execute(select(VerifierAudit))).scalars().all()
    assert row.tier == "verified"
    assert [a.tool for a in audit] == ["create_fixture", "call_as", "delete_fixture"]
    assert all(a.url.startswith(f"https://{HOST}/items") for a in audit)
    assert preview.items == {}  # the fixture was removed by its owner
    everything = json.dumps([runtime, [a.url for a in audit], row.evidence], default=str)
    assert "ghp-test" not in everything


async def test_preview_on_disallowed_host_is_ignored(services: Services, tmp_path: Path) -> None:
    g = gh(services)
    r = g.add_repo(INST, REPO, REPO_ID)
    base, head = "b".ljust(40, "0"), "h".ljust(40, "0")
    r.commits[base] = _tree(tmp_path / "base", BASE_MAIN, config=True)
    r.commits[head] = _tree(tmp_path / "head", HEAD_MAIN, config=True)
    vault = Vault(X25519PrivateKey.generate(), DbCredentialStore(services.sessions))
    services.extra.update(vault=vault, resolver=lambda host: ["76.76.21.21"])
    await install(services)
    g.set_pull(REPO, 1, base, head)
    await post_event(services, "pull_request", pr_payload("opened"))
    await drain(services, include={"route_delivery", "scan_pr"})
    event = {
        "action": "created",
        "installation": {"id": INST},
        "repository": {"id": REPO_ID, "full_name": REPO},
        "deployment": {"sha": head},
        "deployment_status": {
            "state": "success",
            "environment_url": "https://internal.corp.example",
        },
    }
    await post_event(services, "deployment_status", event)
    results = await drain(services, include={"route_delivery", "verify_findings"})
    assert ("verify_findings", "skipped: preview host is not in verifier.preview_hosts") in results
    assert not [c for c in g.check_runs.values() if c["name"] == "AccessGuard / runtime"]
