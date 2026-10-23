"""The broker: executes tool calls against one preview deployment (RV-1..4; PLAN.md §6.14).

It is the only component that holds decrypted credentials, and only for the duration of a call.
Every call passes the policy first, connects to the vetted address with TLS verified against the
preview hostname (httpx 0.28 / httpcore 1.0 ``sni_hostname`` request extension), never follows
redirects, reads at most ``MAX_RESPONSE_BYTES``, and returns only redacted observations. Each call,
refused or not, is written to the audit log.
"""

from __future__ import annotations

import json
import secrets
from dataclasses import dataclass, field
from typing import Any, Protocol

import httpx

from accessguard_verifier.policy import MAX_RESPONSE_BYTES, Policy, PolicyError
from accessguard_verifier.redact import body_shape, find_id
from accessguard_verifier.tools import Identity, Toolset, fill
from accessguard_verifier.vault import Credential, Vault

USER_AGENT = "AccessGuard-Verifier/1.0 (+https://github.com/anish-2025dev/accessguard)"
TIMEOUT = httpx.Timeout(10.0, connect=5.0)


@dataclass
class Observation:
    tool: str
    identity: str
    method: str
    path: str
    status: int | None  # None: refused by policy or network error
    shape: Any = None
    marker_seen: bool = False
    created_id: str | None = None
    refused: str | None = None


class AuditSink(Protocol):
    async def record(self, entry: dict[str, Any]) -> None: ...


@dataclass
class MemoryAudit:
    entries: list[dict[str, Any]] = field(default_factory=list)

    async def record(self, entry: dict[str, Any]) -> None:
        self.entries.append(entry)


class Broker:
    def __init__(
        self,
        *,
        repo_id: int,
        scan_id: str,
        base_url: str,
        tools: Toolset,
        policy: Policy,
        vault: Vault,
        audit: AuditSink,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.repo_id = repo_id
        self.scan_id = scan_id
        self.base_url = base_url.rstrip("/")
        self.tools = tools
        self.policy = policy
        self.vault = vault
        self.audit = audit
        self.transport = transport
        self.marker = f"accessguard-{secrets.token_hex(6)}"  # tags objects this run creates

    async def _headers(self, identity: Identity) -> tuple[dict[str, str], list[str]]:
        headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
        hidden: list[str] = []
        creds: list[Credential | None] = [await self.vault.open(self.repo_id, "vercel_bypass")]
        if identity != "anonymous":
            creds.append(await self.vault.open(self.repo_id, identity))
        for c in creds:
            if c is not None:
                headers.update(c.request_headers())
                hidden += c.secrets()
        return headers, hidden

    async def _send(
        self,
        tool: str,
        identity: Identity,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
        *,
        fixture_call: bool = False,
    ) -> tuple[Observation, bytes]:
        url = self.base_url + path
        obs = Observation(tool, identity, method, path, None)
        raw = b""
        try:
            addr = self.policy.check(method, url, fixture_call=fixture_call)
        except PolicyError as e:
            obs.refused = str(e)
            await self._audit(obs, "refused")
            return obs, raw
        headers, _ = await self._headers(identity)
        if identity != "anonymous" and not any(
            h.lower() in {"authorization", "cookie"} for h in headers
        ):
            obs.refused = f"no credential stored for {identity}"
            await self._audit(obs, "refused")
            return obs, raw
        host = self.policy.preview_host
        pinned = httpx.URL(url).copy_with(host=addr)
        headers["Host"] = host
        try:
            async with (
                httpx.AsyncClient(
                    follow_redirects=False, timeout=TIMEOUT, transport=self.transport
                ) as client,
                client.stream(
                    method,
                    pinned,
                    headers=headers,
                    content=json.dumps(body).encode() if body is not None else None,
                    extensions={"sni_hostname": host},
                ) as resp,
            ):
                obs.status = resp.status_code
                async for chunk in resp.aiter_bytes():
                    raw += chunk
                    if len(raw) > MAX_RESPONSE_BYTES:
                        raw = raw[:MAX_RESPONSE_BYTES]
                        break
        except httpx.HTTPError as e:
            obs.refused = f"network error: {type(e).__name__}"
            await self._audit(obs, "error")
            return obs, raw
        obs.shape = body_shape(raw)
        obs.marker_seen = self.marker.encode() in raw
        await self._audit(obs, "sent")
        return obs, raw

    async def _audit(self, obs: Observation, decision: str) -> None:
        await self.audit.record(
            {
                "scan_id": self.scan_id,
                "tool": obs.tool,
                "identity": obs.identity,
                "method": obs.method,
                "url": self.base_url + obs.path,  # ids only; query strings are never sent
                "status": obs.status,
                "decision": obs.refused or decision,
            }
        )

    # ---- tools ------------------------------------------------------------------------------
    async def call_as(
        self, identity: Identity, endpoint: str, path_params: dict[str, str] | None = None
    ) -> Observation:
        t = self.tools.targets.get(endpoint)
        if t is None or identity not in self.tools.identities:
            return Observation("call_as", identity, "", endpoint, None, refused="unknown tool args")
        try:
            path = fill(t.path, path_params or {})
        except KeyError as e:
            return Observation("call_as", identity, t.method, t.path, None, refused=f"missing {e}")
        obs, _ = await self._send("call_as", identity, t.method, path)
        return obs

    async def create_fixture(
        self, identity: Identity, endpoint: str, body: dict[str, Any] | None = None
    ) -> Observation:
        path = self.tools.collections.get(endpoint)
        if path is None or identity == "anonymous" or identity not in self.tools.identities:
            return Observation(
                "create_fixture", identity, "POST", endpoint, None, refused="unknown tool args"
            )
        payload = {**(body or {})}
        payload.setdefault("title", self.marker)  # the marker identifies the object later
        payload.setdefault("name", self.marker)
        obs, raw = await self._send(
            "create_fixture", identity, "POST", path, payload, fixture_call=True
        )
        if obs.status is not None and 200 <= obs.status < 300:
            obs.created_id = find_id(raw)
            if obs.created_id:
                self.policy.fixtures.add(obs.created_id)
        return obs

    async def delete_fixture(
        self, identity: Identity, endpoint: str, fixture_id: str
    ) -> Observation:
        """Remove an object this run created (the policy refuses any other DELETE)."""
        path = self.tools.cleanups.get(endpoint)
        t = self.tools.targets.get(endpoint)
        if path is None or t is None or not t.params or fixture_id not in self.policy.fixtures:
            return Observation(
                "delete_fixture", identity, "DELETE", endpoint, None, refused="not a fixture"
            )
        obs, _ = await self._send(
            "delete_fixture", identity, "DELETE", fill(path, {t.params[-1]: fixture_id})
        )
        return obs
