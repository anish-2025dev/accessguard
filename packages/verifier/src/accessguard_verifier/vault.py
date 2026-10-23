"""Credential vault (RV-1; PLAN.md §6.14): envelope encryption, opened only inside the broker.

Each stored credential gets its own 256-bit data key (DEK) and is sealed with AES-256-GCM under it,
with ``repo_id|label`` as associated data so a ciphertext cannot be replayed for another
repository or label. The DEK is wrapped for the verifier's X25519 key pair (ephemeral X25519
agreement, HKDF-SHA256, AES-256-GCM), so the component that *stores* credentials (the API, via
``Sealer``) holds only the public key and can never decrypt them; only the verifier process holds
the private key (``ACCESSGUARD_VERIFIER_PRIVATE_KEY`` in the platform secret store) and opens
credentials at call time. The decrypted ``Credential`` cannot be printed or pickled.

cryptography 50.0.2: ``AESGCM(key).encrypt(nonce, data, associated_data)``,
``X25519PrivateKey.exchange``, ``HKDF(algorithm, length, salt, info).derive``
(https://cryptography.io/en/latest/hazmat/primitives/aead/,
https://cryptography.io/en/latest/hazmat/primitives/asymmetric/x25519/,
https://cryptography.io/en/latest/hazmat/primitives/key-derivation-functions/#hkdf).
"""

from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass
from typing import Literal, Protocol

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
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


def _key_from_env(var: str) -> bytes:
    raw = os.environ.get(var, "")
    key = base64.b64decode(raw) if raw else b""
    if len(key) != 32:
        raise RuntimeError(f"{var} must be 32 bytes, base64-encoded")
    return key


def private_key_from_env(var: str = "ACCESSGUARD_VERIFIER_PRIVATE_KEY") -> X25519PrivateKey:
    return X25519PrivateKey.from_private_bytes(_key_from_env(var))


def public_key_from_env(var: str = "ACCESSGUARD_VERIFIER_PUBLIC_KEY") -> X25519PublicKey:
    return X25519PublicKey.from_public_bytes(_key_from_env(var))


def new_keypair() -> tuple[str, str]:
    """(private, public), base64: for `accessguard-verifier keygen`."""
    k = X25519PrivateKey.generate()
    return (
        base64.b64encode(k.private_bytes_raw()).decode(),
        base64.b64encode(k.public_key().public_bytes_raw()).decode(),
    )


def _seal(key: bytes, data: bytes, aad: bytes) -> bytes:
    nonce = os.urandom(NONCE)
    return nonce + AESGCM(key).encrypt(nonce, data, aad)


def _open(key: bytes, blob: bytes, aad: bytes) -> bytes:
    return AESGCM(key).decrypt(blob[:NONCE], blob[NONCE:], aad)


def _wrap_key(shared: bytes, aad: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"ag-vault|" + aad).derive(
        shared
    )


def _aad(repo_id: int, label: str) -> bytes:
    return f"accessguard-vault|{repo_id}|{label}".encode()


class Sealer:
    """Stores credentials. Holds only the verifier's public key: cannot open anything."""

    def __init__(self, verifier_public_key: X25519PublicKey, store: CredentialStore) -> None:
        self._pub = verifier_public_key
        self.store = store

    async def put(self, repo_id: int, label: str, credential: CredentialIn) -> None:
        if label not in LABELS:
            raise ValueError("unknown credential label")
        aad = _aad(repo_id, label)
        dek = AESGCM.generate_key(bit_length=256)
        ct = _seal(dek, credential.model_dump_json().encode(), aad)
        eph = X25519PrivateKey.generate()
        wrap = _wrap_key(eph.exchange(self._pub), aad)
        wrapped = eph.public_key().public_bytes_raw() + _seal(wrap, dek, aad)
        await self.store.put(repo_id, label, Sealed(ct, wrapped))

    async def delete(self, repo_id: int, label: str) -> None:
        await self.store.delete(repo_id, label)

    async def labels(self, repo_id: int) -> list[str]:
        return [lab for lab in LABELS if await self.store.get(repo_id, lab) is not None]


class Vault:
    """Opens credentials. Lives in the verifier process only (holds the private key)."""

    def __init__(self, private_key: X25519PrivateKey, store: CredentialStore) -> None:
        self._priv = private_key
        self.store = store

    def sealer(self) -> Sealer:
        return Sealer(self._priv.public_key(), self.store)

    async def put(self, repo_id: int, label: str, credential: CredentialIn) -> None:
        await self.sealer().put(repo_id, label, credential)

    async def open(self, repo_id: int, label: str) -> Credential | None:
        """For the broker only. Returns None when nothing is stored."""
        sealed = await self.store.get(repo_id, label)
        if sealed is None:
            return None
        aad = _aad(repo_id, label)
        eph = X25519PublicKey.from_public_bytes(sealed.wrapped_dek[:32])
        dek = _open(_wrap_key(self._priv.exchange(eph), aad), sealed.wrapped_dek[32:], aad)
        data = _open(dek, sealed.ciphertext, aad)
        return Credential(CredentialIn.model_validate(json.loads(data)))


class MemoryStore:
    def __init__(self) -> None:
        self.rows: dict[tuple[int, str], Sealed] = {}

    async def put(self, repo_id: int, label: str, sealed: Sealed) -> None:
        self.rows[(repo_id, label)] = sealed

    async def get(self, repo_id: int, label: str) -> Sealed | None:
        return self.rows.get((repo_id, label))

    async def delete(self, repo_id: int, label: str) -> None:
        self.rows.pop((repo_id, label), None)
