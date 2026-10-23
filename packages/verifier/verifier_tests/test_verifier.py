"""Runtime verifier (RV-1..4): vault, policy, redaction, broker, plans, comparator."""

from __future__ import annotations

import asyncio
import json
import os
import pickle
import re

import httpx
import pytest
from accessguard_verifier.broker import Broker, MemoryAudit
from accessguard_verifier.policy import Policy, PolicyError, public_ip
from accessguard_verifier.redact import mask_text
from accessguard_verifier.tools import build_toolset
from accessguard_verifier.vault import CredentialIn, MemoryStore, Vault
from accessguard_verifier.verify import verify
from authgraph.facts.models import Endpoint, Finding, Loc

HOST = "pr-7-acme.vercel.app"
PUBLIC_IP = "76.76.21.21"


def _vault() -> Vault:
    return Vault(os.urandom(32), MemoryStore())


def test_vault_envelope_and_no_leaks() -> None:
    async def go() -> None:
        v = _vault()
        await v.put(1, "user_a", CredentialIn(type="bearer", token="tok-a-123456"))
        sealed = await v.store.get(1, "user_a")
        assert sealed is not None and b"tok-a-123456" not in sealed.ciphertext
        cred = await v.open(1, "user_a")
        assert cred is not None
        assert cred.request_headers() == {"Authorization": "Bearer tok-a-123456"}
        assert "tok-a" not in repr(cred) and "tok-a" not in str(cred)
        with pytest.raises(TypeError):
            pickle.dumps(cred)
        # Ciphertext is bound to (repo, label): moving it to another repo fails to open.
        await v.store.put(2, "user_a", sealed)
        with pytest.raises(Exception):  # noqa: B017 - cryptography InvalidTag
            await v.open(2, "user_a")

    asyncio.run(go())


@pytest.mark.parametrize(
    ("addr", "ok"),
    [
        ("76.76.21.21", True),
        ("10.0.0.5", False),
        ("127.0.0.1", False),
        ("169.254.169.254", False),
        ("100.64.0.1", False),
        ("::ffff:10.0.0.1", False),
        ("fd00::1", False),
        ("2606:4700::1111", True),
    ],
)
def test_ssrf_guard(addr: str, ok: bool) -> None:
    assert public_ip(addr) is ok


def _policy(resolve: list[str] | None = None) -> Policy:
    return Policy(HOST, ["*.vercel.app"], resolver=lambda h: resolve or [PUBLIC_IP])


def test_policy_refusals() -> None:
    p = _policy()
    assert p.check("GET", f"https://{HOST}/items") == PUBLIC_IP
    for method, url, msg in [
        ("GET", f"http://{HOST}/items", "https"),
        ("GET", "https://evil.example.com/x", "preview deployment"),
        ("GET", f"https://user:pw@{HOST}/x", "credentials"),
        ("POST", f"https://{HOST}/items", "create_fixture"),
        ("DELETE", f"https://{HOST}/items/9", "objects this run created"),
    ]:
        with pytest.raises(PolicyError, match=msg):
            p.check(method, url)
    with pytest.raises(PolicyError, match="non-public"):
        _policy(["10.1.2.3"]).check("GET", f"https://{HOST}/items")
    p.fixtures.add("9")
    assert p.check("DELETE", f"https://{HOST}/items/9")
    q = Policy(HOST, ["*.vercel.app"], budget=1, resolver=lambda h: [PUBLIC_IP])
    q.check("GET", f"https://{HOST}/a")
    with pytest.raises(PolicyError, match="budget"):
        q.check("GET", f"https://{HOST}/a")


def test_redaction() -> None:
    text = (
        "token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTYifQ.c2lnbmF0dXJl mail bob@example.com key "
        + "a" * 40
    )
    out = mask_text(text, ["sekret-value"])
    assert "eyJ" not in out and "bob@" not in out and "a" * 40 not in out


class PreviewApp:
    """In-process stand-in for a preview deployment with token auth and an IDOR bug."""

    def __init__(self, idor: bool) -> None:
        self.idor = idor
        self.items: dict[str, dict[str, str]] = {}
        self.hosts: set[str] = set()
        self.sni: set[str] = set()

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.hosts.add(request.headers.get("host", ""))
        self.sni.add(str(request.extensions.get("sni_hostname")))
        user = {"Bearer tok-a-123456": "a", "Bearer tok-b-123456": "b"}.get(
            request.headers.get("authorization", "")
        )
        if request.headers.get("x-vercel-protection-bypass") != "bypass-123456":
            return httpx.Response(401, json={"error": "vercel protection"})
        if user is None:
            return httpx.Response(401, json={"error": "login"})
        path = request.url.path
        if request.method == "POST" and path == "/api/items":
            body = json.loads(request.content)
            item_id = str(len(self.items) + 1)
            self.items[item_id] = {"owner": user, "title": body["title"]}
            return httpx.Response(201, json={"id": item_id, "owner_email": f"{user}@x.io"})
        m = re.fullmatch(r"/api/items/(\w+)", path)
        if m and m.group(1) in self.items:
            item = self.items[m.group(1)]
            if not self.idor and item["owner"] != user:
                return httpx.Response(404, json={"error": "not found"})
            if request.method == "DELETE":
                del self.items[m.group(1)]
                return httpx.Response(204)
            return httpx.Response(200, json={"id": m.group(1), **item})
        return httpx.Response(404)


def _facts() -> tuple[list[Finding], list[Endpoint]]:
    loc = Loc(path="app/items.py", line=1)
    eps = [
        Endpoint(
            id="GET /api/items/{item_id}",
            method="GET",
            path="/api/items/{item_id}",
            framework="fastapi",
            handler="h",
            loc=loc,
        ),
        Endpoint(
            id="DELETE /api/items/{item_id}",
            method="DELETE",
            path="/api/items/{item_id}",
            framework="fastapi",
            handler="h",
            loc=loc,
        ),
        Endpoint(
            id="POST /api/items",
            method="POST",
            path="/api/items",
            framework="fastapi",
            handler="h",
            loc=loc,
        ),
    ]
    f = Finding(
        rule_id="AG-IDOR-001",
        fingerprint="fp1",
        severity="medium",
        tier="heuristic",
        title="t",
        endpoint_id="GET /api/items/{item_id}",
        loc=loc,
    )
    return [f], eps


async def _run(app: PreviewApp) -> tuple[str, MemoryAudit]:
    vault = _vault()
    await vault.put(7, "user_a", CredentialIn(type="bearer", token="tok-a-123456"))
    await vault.put(7, "user_b", CredentialIn(type="bearer", token="tok-b-123456"))
    await vault.put(7, "vercel_bypass", CredentialIn(type="bypass", token="bypass-123456"))
    findings, eps = _facts()
    tools = build_toolset(findings, eps, ("user_a", "user_b", "anonymous"))
    audit = MemoryAudit()
    broker = Broker(
        repo_id=7,
        scan_id="s1",
        base_url=f"https://{HOST}",
        tools=tools,
        policy=_policy(),
        vault=vault,
        audit=audit,
        transport=httpx.MockTransport(app),
    )
    [result] = await verify(tools, broker)
    # Nothing secret reaches observations or the audit log.
    blob = json.dumps(audit.entries) + repr(result)
    assert "tok-a" not in blob and "tok-b" not in blob and "bypass-123456" not in blob
    assert "a@x.io" not in blob
    return result.decision, audit


def test_idor_is_verified_against_a_vulnerable_preview() -> None:
    app = PreviewApp(idor=True)
    decision, audit = asyncio.run(_run(app))
    assert decision == "verified"
    assert app.hosts == {HOST} and app.sni == {HOST}  # pinned IP, real Host and SNI
    assert app.items == {}  # the fixture was cleaned up by its owner
    assert [e["decision"] for e in audit.entries] == ["sent", "sent", "sent"]


def test_idor_is_refuted_when_ownership_is_enforced() -> None:
    decision, _ = asyncio.run(_run(PreviewApp(idor=False)))
    assert decision == "refuted"


def test_tool_schemas_only_cover_flagged_endpoints() -> None:
    findings, eps = _facts()
    tools = build_toolset(findings, eps, ("user_a", "user_b"))
    schemas = {t["name"]: t for t in tools.schemas()}
    assert schemas["call_as"]["inputSchema"]["properties"]["endpoint"]["enum"] == [
        "GET /api/items/{item_id}"
    ]
    assert "create_fixture" in schemas
