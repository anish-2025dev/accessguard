"""Tools generated from engine facts by templates (RV-2; PLAN.md §6.14).

The planner can only call these tools, only on the endpoints the engine flagged, and only with
the identities the maintainer configured. Tool definitions are produced here from findings; an
LLM never writes or extends them. The JSON schemas are MCP ``inputSchema`` compatible
(https://modelcontextprotocol.io/specification/2025-06-18/server/tools).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Literal

from authgraph.facts.models import Endpoint, Finding

Identity = Literal["user_a", "user_b", "anonymous"]
PARAM = re.compile(r"\{(\w+)(?::\w+)?\}|:(\w+)")
VERIFIABLE_RULES = frozenset(
    {"AG-AUTH-001", "AG-AUTH-002", "AG-AUTH-003", "AG-ROLE-001", "AG-IDOR-001", "AG-IDOR-002"}
)


@dataclass(frozen=True)
class Target:
    """An endpoint the engine flagged, as the broker may address it."""

    endpoint_id: str  # "GET /items/{item_id}"
    method: str
    path: str
    params: tuple[str, ...]
    finding: str  # fingerprint
    rule_id: str


@dataclass
class Toolset:
    targets: dict[str, Target] = field(default_factory=dict)
    # collection endpoint (POST) per item endpoint, for create_fixture
    collections: dict[str, str] = field(default_factory=dict)
    # DELETE path of the item endpoint, used only to remove this run's own fixtures
    cleanups: dict[str, str] = field(default_factory=dict)
    identities: tuple[Identity, ...] = ("anonymous",)

    def schemas(self) -> list[dict[str, Any]]:
        ids = sorted(self.targets)
        call_as = {
            "name": "call_as",
            "description": "Call one flagged endpoint of the preview deployment as a test "
            "identity. Returns status, response shape and whether the given fixture marker "
            "is present. Reads only, except on objects this run created.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "identity": {"enum": list(self.identities)},
                    "endpoint": {"enum": ids},
                    "path_params": {"type": "object", "additionalProperties": {"type": "string"}},
                    "marker": {"type": "string"},
                },
                "required": ["identity", "endpoint"],
                "additionalProperties": False,
            },
        }
        tools = [call_as]
        if self.collections:
            tools.append(
                {
                    "name": "create_fixture",
                    "description": "Create a marked test object as an identity through the "
                    "collection endpoint of a flagged item endpoint; returns its id.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "identity": {"enum": [i for i in self.identities if i != "anonymous"]},
                            "endpoint": {"enum": sorted(self.collections)},
                            "body": {"type": "object"},
                        },
                        "required": ["identity", "endpoint"],
                        "additionalProperties": False,
                    },
                }
            )
        return tools


def path_params(path: str) -> tuple[str, ...]:
    return tuple(a or b for a, b in PARAM.findall(path))


def build_toolset(
    findings: list[Finding], endpoints: list[Endpoint], identities: tuple[Identity, ...]
) -> Toolset:
    by_id = {e.id: e for e in endpoints}
    ts = Toolset(identities=identities)
    for f in findings:
        e = by_id.get(f.endpoint_id or "")
        if f.rule_id not in VERIFIABLE_RULES or e is None or "<dynamic>" in e.path:
            continue
        ts.targets[e.id] = Target(
            e.id, e.method, e.path, path_params(e.path), f.fingerprint, f.rule_id
        )
        if f.rule_id.startswith("AG-IDOR") and path_params(e.path):
            collection = re.sub(r"/(\{[^}]+\}|:\w+)$", "", e.path) or "/"
            create = by_id.get(f"POST {collection}") or by_id.get(f"POST {collection}/")
            if create is not None:
                ts.collections[e.id] = create.path
                delete = by_id.get(f"DELETE {e.path}")
                if delete is not None:
                    ts.cleanups[e.id] = delete.path
    return ts


def fill(path: str, values: dict[str, str]) -> str:
    def sub(m: re.Match[str]) -> str:
        name = m.group(1) or m.group(2)
        if name not in values:
            raise KeyError(name)
        return re.sub(r"[^A-Za-z0-9._~-]", "", values[name])[:128]

    return PARAM.sub(sub, path)
