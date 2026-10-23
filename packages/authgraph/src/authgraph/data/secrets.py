"""Service-role and secret keys in client code (FR-3.10, AG-SECRET-001).

Detectors (values are never stored; findings carry a kind, a location and a short hash):

* a JWT literal whose payload's ``role`` claim is ``service_role`` (Supabase service key;
  https://supabase.com/docs/guides/api/api-keys);
* ``sb_secret_...`` Supabase secret API keys (same page, "new API keys");
* ``sk_live_...`` Stripe secret keys and PEM private keys;
* an environment variable whose name carries a client-bundle prefix (``NEXT_PUBLIC_``, ``VITE_``,
  ``EXPO_PUBLIC_``, ``REACT_APP_``, ``NUXT_PUBLIC_``, ``PUBLIC_``, ``GATSBY_``) and names a secret
  (``SERVICE_ROLE``, ``SECRET``, ``PRIVATE_KEY``): bundlers inline these into client code
  (https://nextjs.org/docs/app/guides/environment-variables#bundling-environment-variables-for-
  the-browser, https://vite.dev/guide/env-and-mode).

A literal key is reported only in client code: a ``"use client"`` module, a browser framework
file (``.vue``, ``.svelte``, ``.html``), or a file under a client directory and not under a
server one (``api/``, ``server/``, ``supabase/functions/``, ``*.server.*``, route handlers).
"""

from __future__ import annotations

import base64
import hashlib
import json
import re

from authgraph.facts.models import Loc, SecretExposure
from authgraph.workspace.tree import MAX_FILE_BYTES, SourceTree, is_generated_path, is_test_path

SCANNED = re.compile(r"\.([cm]?[jt]sx?|vue|svelte|html|astro)$|(^|/)\.env(\.[\w.-]+)?$")
JWT = re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.(eyJ[A-Za-z0-9_-]{8,})\.[A-Za-z0-9_-]{8,}")
SB_SECRET = re.compile(r"\bsb_secret_[A-Za-z0-9_-]{16,}")
STRIPE_SECRET = re.compile(r"\bsk_live_[A-Za-z0-9]{16,}")
PEM_KEY = re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----")
PUBLIC_PREFIX = r"(NEXT_PUBLIC_|VITE_|EXPO_PUBLIC_|REACT_APP_|NUXT_PUBLIC_|PUBLIC_|GATSBY_)"
SECRET_ENV = re.compile(
    rf"\b{PUBLIC_PREFIX}\w*(SERVICE_ROLE|SECRET|PRIVATE_KEY|PRIV_KEY)\w*\b", re.I
)
CLIENT_DIRS = re.compile(
    r"(^|/)(components|pages|app|src|public|static|client|frontend|web|www|views|hooks|lib|"
    r"mobile|screens)/"
)
SERVER_HINT = re.compile(
    r"(^|/)(api|server|backend|functions|supabase/functions|scripts|migrations|middleware)(/|\.)"
    r"|\.server\.[cm]?[jt]sx?$|(^|/)route\.[cm]?[jt]s$|(^|/)(next|vite|nuxt|astro)\.config\."
)
USE_CLIENT = re.compile(r"""^\s*['"]use client['"]""", re.M)
USE_SERVER = re.compile(r"""^\s*['"]use server['"]""", re.M)


def is_client_file(path: str, text: str) -> bool:
    if USE_SERVER.search(text[:2000]):
        return False
    if USE_CLIENT.search(text[:2000]) or path.endswith((".vue", ".svelte", ".html", ".astro")):
        return True
    return bool(CLIENT_DIRS.search(path)) and not SERVER_HINT.search(path)


def _jwt_role(token: str) -> str | None:
    payload = token.split(".")[1]
    try:
        data = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    except (ValueError, json.JSONDecodeError):
        return None
    role = data.get("role") if isinstance(data, dict) else None
    return role if isinstance(role, str) else None


def _h(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:12]


def scan_text(path: str, text: str) -> list[SecretExposure]:
    out: list[SecretExposure] = []
    client = is_client_file(path, text)
    env_file = bool(re.search(r"(^|/)\.env", path))
    for ln, line in enumerate(text.splitlines(), start=1):
        if len(line) > 5000:
            continue
        if client:
            for m in JWT.finditer(line):
                if _jwt_role(m.group(0)) == "service_role":
                    out.append(_exp("supabase_service_role_jwt", path, ln, m.group(0)))
            for rx, kind in (
                (SB_SECRET, "supabase_secret_key"),
                (STRIPE_SECRET, "stripe_secret_key"),
                (PEM_KEY, "private_key"),
            ):
                for m in rx.finditer(line):
                    out.append(_exp(kind, path, ln, m.group(0)))
        for m in SECRET_ENV.finditer(line):
            # Defining or reading the variable anywhere puts it in the client bundle.
            if env_file or client or "process.env" in line or "import.meta.env" in line:
                out.append(_exp("secret_env_public_prefix", path, ln, m.group(0), m.group(0)))
    return out


def _exp(kind: str, path: str, line: int, value: str, name: str = "") -> SecretExposure:
    detail = f"{name} " if name else ""
    return SecretExposure(
        kind=kind,
        client_side=True,
        loc=Loc(path=path, line=line),
        detail=f"{detail}#{_h(value)}",  # identity for dedup; never the value
    )


def analyze_secrets(tree: SourceTree) -> list[SecretExposure]:
    out: list[SecretExposure] = []
    for path in tree.paths():
        if not SCANNED.search(path) or is_generated_path(path) or is_test_path(path):
            continue
        data = tree.read(path)
        if len(data) > MAX_FILE_BYTES:
            continue
        out += scan_text(path, data.decode("utf-8", "replace"))
    return out
