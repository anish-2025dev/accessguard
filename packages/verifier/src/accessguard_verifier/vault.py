"""Credential vault (RV-1; PLAN.md §6.14): envelope encryption, decrypted only inside the broker.

Each repository gets its own 256-bit data key (DEK). A credential is sealed with AES-256-GCM
under the DEK, with ``repo_id|label`` as associated data so a ciphertext cannot be replayed for
another repository or label. The DEK is itself sealed with the master key (KEK) from the
platform secret store (``ACCESSGUARD_VAULT_MASTER_KEY``, 32 bytes, base64). Only ciphertext and
the wrapped DEK are stored (``verifier_credentials``). Nothing in this module returns a
credential to a caller outside the broker: ``Vault.open`` is used by ``Broker`` only, and the
``Credential`` object refuses to be printed or serialised.

cryptography 50.0.2: ``AESGCM(key).encrypt(nonce, data, associated_data)`` /
``.decrypt(...)``, 96-bit random nonces (https://cryptography.io/en/latest/hazmat/primitives/
aead/#cryptography.hazmat.primitives.ciphers.aead.AESGCM).
"""

from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass
from typing import Literal, Protocol

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pydantic import BaseModel, ConfigDict, Field, field_validator

NONCE = 12
LABELS = ("user_a", "user_b", "vercel_bypass")
Label = Literal["user_a", "user_b", "vercel_bypass"]


class CredentialIn(BaseModel):
    """What a maintainer uploads for a test account (``POST /verifier/credentials``)."""

    model_config = ConfigDict(extra="forbid")
    type: Literal["bearer", "cookie", "headers", "bypass"]
    token: str | None = Field(default=None, max_length=8192)
    cookie: str | None = Field(default=None, max_length=8192)
    headers: dict[str, str] = Field(default_factory=dict)

    @field_validator("headers")
    @classmethod
    def _limit(cls, v: dict[str, str]) -> dict[str, str]:
        if len(v) > 10 or any(len(k) > 100 or len(x) > 8192 for k, x in v.items()):
            raise ValueError("too many or too large headers")
        return v


class Credential:
    """Decrypted credential; usable by the broker, never printable."""

    __slots__ = ("_data",)

    def __init__(self, data: CredentialIn) -> None:
        self._data = data

    def request_headers(self) -> dict[str, str]:
        d = self._data
        if d.type == "bearer" and d.token:
            return {"Authorization": f"Bearer {d.token}"}
        if d.type == "cookie" and d.cookie:
            return {"Cookie": d.cookie}
        if d.type == "bypass" and d.token:
            # Vercel Protection Bypass for Automation (https://vercel.com/docs/deployment-
            # protection/methods-to-bypass-deployment-protection/protection-bypass-automation)
            return {"x-vercel-protection-bypass": d.token}
        return dict(d.headers)

    def secrets(self) -> list[str]:
        """Values the redactor must never let through."""
        d = self._data
        vals = [d.token or "", d.cookie or "", *d.headers.values()]
        return [v for v in vals if len(v) >= 6]

    def __repr__(self) -> str:
        return "Credential(<redacted>)"

    __str__ = __repr__

    def __reduce__(self) -> str | tuple[object, ...]:
        raise TypeError("credentials cannot be pickled")


@dataclass(frozen=True)
class Sealed:
    ciphertext: bytes
    wrapped_dek: bytes


class CredentialStore(Protocol):
    async def put(self, repo_id: int, label: str, sealed: Sealed) -> None: ...
    async def get(self, repo_id: int, label: str) -> Sealed | None: ...
    async def delete(self, repo_id: int, label: str) -> None: ...


def master_key_from_env(var: str = "ACCESSGUARD_VAULT_MASTER_KEY") -> bytes:
    raw = os.environ.get(var, "")
    key = base64.b64decode(raw) if raw else b""
    if len(key) != 32:
        raise RuntimeError(f"{var} must be 32 bytes, base64-encoded")
    return key


def _seal(key: bytes, data: bytes, aad: bytes) -> bytes:
    nonce = os.urandom(NONCE)
    return nonce + AESGCM(key).encrypt(nonce, data, aad)


def _open(key: bytes, blob: bytes, aad: bytes) -> bytes:
    return AESGCM(key).decrypt(blob[:NONCE], blob[NONCE:], aad)


class Vault:
    def __init__(self, master_key: bytes, store: CredentialStore) -> None:
        if len(master_key) != 32:
            raise ValueError("master key must be 32 bytes")
        self._kek = master_key
        self.store = store

    @staticmethod
    def _aad(repo_id: int, label: str) -> bytes:
        return f"accessguard-vault|{repo_id}|{label}".encode()

    async def put(self, repo_id: int, label: Label, credential: CredentialIn) -> None:
        if label not in LABELS:
            raise ValueError("unknown credential label")
        dek = AESGCM.generate_key(bit_length=256)
        aad = self._aad(repo_id, label)
        ct = _seal(dek, credential.model_dump_json().encode(), aad)
        await self.store.put(repo_id, label, Sealed(ct, _seal(self._kek, dek, aad)))

    async def open(self, repo_id: int, label: Label) -> Credential | None:
        """For the broker only. Returns None when nothing is stored."""
        sealed = await self.store.get(repo_id, label)
        if sealed is None:
            return None
        aad = self._aad(repo_id, label)
        dek = _open(self._kek, sealed.wrapped_dek, aad)
        return Credential(
            CredentialIn.model_validate(json.loads(_open(dek, sealed.ciphertext, aad)))
        )

    async def labels(self, repo_id: int) -> list[str]:
        return [lab for lab in LABELS if await self.store.get(repo_id, lab) is not None]


class MemoryStore:
    def __init__(self) -> None:
        self.rows: dict[tuple[int, str], Sealed] = {}

    async def put(self, repo_id: int, label: str, sealed: Sealed) -> None:
        self.rows[(repo_id, label)] = sealed

    async def get(self, repo_id: int, label: str) -> Sealed | None:
        return self.rows.get((repo_id, label))

    async def delete(self, repo_id: int, label: str) -> None:
        self.rows.pop((repo_id, label), None)
