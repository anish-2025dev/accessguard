"""AG-DATA-001/002/003 and AG-SECRET-001: data-layer exposure and client-side secrets
(FR-3.8, FR-3.9, FR-3.10; PLAN.md §6.5).

Diff semantics: an exposure is reported when its (resource, role, reason) is new in the head,
or when it already existed but now grants more operations. A secret is reported when its
(kind, value hash) is new in the head, so moving a file or a line never re-reports it.
"""

from __future__ import annotations

from collections.abc import Iterable

from authgraph.facts.models import (
    DataExposure,
    EvidenceStep,
    FactGraph,
    Finding,
    SecretExposure,
    Severity,
    Tier,
)
from authgraph.rules.base import RuleContext, finalize

SEVERITY_RANK: dict[Severity, int] = {"low": 0, "medium": 1, "high": 2, "critical": 3}
WRITES = frozenset({"insert", "update", "delete", "write", "create"})
DATA_RULES: dict[str, tuple[str, Tier]] = {
    "rls_disabled": ("AG-DATA-001", "deterministic"),
    "policy_true_write": ("AG-DATA-001", "deterministic"),
    "security_definer_view": ("AG-DATA-001", "deterministic"),
    "null_fail_open": ("AG-DATA-002", "heuristic"),
    "firebase_open": ("AG-DATA-003", "deterministic"),
    "firebase_auth_only": ("AG-DATA-003", "heuristic"),
}
EXPLAIN = {
    "rls_disabled": "Row level security is off on a table the Supabase Data API exposes",
    "policy_true_write": "A permissive policy lets this role write every row",
    "security_definer_view": "The view runs as its owner, so callers bypass RLS on its tables",
    "null_fail_open": "The policy passes when a value is NULL (anonymous caller or orphan row)",
    "firebase_open": "The Firebase rule allows this access without any condition",
    "firebase_auth_only": "The Firebase rule only checks that someone is signed in",
}
FIX = {
    "rls_disabled": "`alter table ... enable row level security;` and add policies, or revoke "
    "the anon/authenticated privileges.",
    "policy_true_write": "Replace `true` with a predicate on the row owner, e.g. "
    "`(select auth.uid()) = user_id`.",
    "security_definer_view": "Create the view `with (security_invoker = true)`.",
    "null_fail_open": "Drop the `IS NULL` branch or require `auth.uid() IS NOT NULL`.",
    "firebase_open": "Require `request.auth != null` and an ownership check on the document.",
    "firebase_auth_only": "Compare `request.auth.uid` with the document's owner field or path.",
}


def _key(e: DataExposure) -> tuple[str, str, str]:
    return (e.resource, e.role, e.reason)


def _severity(e: DataExposure, tier: Tier) -> Severity:
    write = bool(e.ops & WRITES)
    if tier == "heuristic":
        return "high" if write else "medium"
    if e.role in {"anon", "public"} and write:
        return "critical"
    return "high"


class _DataRule:
    id = ""
    title = "Data exposed beyond its intended roles"
    default_severity = "high"
    tier = "deterministic"

    def evaluate(
        self, head: FactGraph, base: FactGraph | None, ctx: RuleContext
    ) -> Iterable[Finding]:
        before = {_key(e): e for e in (base.data_exposures if base else [])}
        # New or widened grants, grouped per (resource, reason): one finding lists every role.
        groups: dict[tuple[str, str], list[tuple[DataExposure, set[str]]]] = {}
        seen: set[tuple[str, str, str]] = set()
        for e in head.data_exposures:
            rule, _ = DATA_RULES.get(e.reason, ("", "advisory"))
            if rule != self.id or _key(e) in seen:
                continue
            seen.add(_key(e))
            old = before.get(_key(e))
            new_ops = e.ops - old.ops if old else set(e.ops)
            if new_ops:
                groups.setdefault((e.resource, e.reason), []).append((e, new_ops))
        for (resource, reason), items in sorted(groups.items()):
            _, tier = DATA_RULES[reason]
            first = items[0][0]
            roles = sorted({e.role for e, _ in items})
            ops = sorted(set().union(*(o for _, o in items)))
            severity = max((_severity(e, tier) for e, _ in items), key=SEVERITY_RANK.__getitem__)
            yield finalize(
                Finding(
                    rule_id=self.id,
                    severity=severity,
                    tier=tier,
                    title=f"{resource}: {', '.join(roles)} can {', '.join(ops)}",
                    resource=resource,
                    loc=first.loc,
                    delta=f"{reason};{','.join(roles)};{','.join(ops)}",
                    evidence=[
                        EvidenceStep(message=EXPLAIN.get(reason, reason), loc=first.loc),
                        *([EvidenceStep(message=first.detail)] if first.detail else []),
                    ],
                    suggested_fix=FIX.get(reason),
                ),
                ctx,
            )


class SupabaseExposure(_DataRule):
    id = "AG-DATA-001"
    title = "Supabase table or view exposed"


class SupabaseNullFailOpen(_DataRule):
    id = "AG-DATA-002"
    title = "Supabase policy fails open on NULL"
    tier = "heuristic"


class FirebaseOpenRule(_DataRule):
    id = "AG-DATA-003"
    title = "Firebase rule open to everyone or to any signed-in user"


SECRET_TITLES = {
    "supabase_service_role_jwt": "Supabase service-role key in client code",
    "supabase_secret_key": "Supabase secret API key in client code",
    "stripe_secret_key": "Stripe secret key in client code",
    "private_key": "Private key in client code",
    "secret_env_public_prefix": "Secret environment variable with a client-bundle prefix",
}


def _name_of(s: SecretExposure) -> str:
    return s.detail.split("#")[0].strip() or "value redacted"


class ClientSecret:
    """AG-SECRET-001: service-role / secret key or secret env name reaches client code."""

    id = "AG-SECRET-001"
    title = "Secret reaches client code"
    default_severity = "critical"
    tier = "deterministic"

    def evaluate(
        self, head: FactGraph, base: FactGraph | None, ctx: RuleContext
    ) -> Iterable[Finding]:
        def key(s: SecretExposure) -> tuple[str, str]:
            return (s.kind, s.detail)

        before = {key(s) for s in (base.secrets if base else [])}
        seen: set[tuple[str, str]] = set()
        for s in head.secrets:
            if not s.client_side or key(s) in before or key(s) in seen:
                continue
            seen.add(key(s))
            title = SECRET_TITLES.get(s.kind, s.kind)
            yield finalize(
                Finding(
                    rule_id=self.id,
                    severity="high" if s.kind == "secret_env_public_prefix" else "critical",
                    tier="deterministic",
                    title=title,
                    resource=f"{s.loc.path}#{s.kind}",
                    loc=s.loc,
                    delta=f"{s.kind};{s.detail}",
                    evidence=[
                        EvidenceStep(
                            message=f"{title} ({_name_of(s)}); code shipped to browsers "
                            "or apps is public",
                            loc=s.loc,
                        )
                    ],
                    suggested_fix="Move the key to server-only code (an API route, edge function "
                    "or backend), rotate it, and use the anon/publishable key in the client.",
                ),
                ctx,
            )
