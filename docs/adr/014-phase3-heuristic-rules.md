# ADR 014: Phase 3 heuristic rules: role consistency and IDOR candidates

- Status: Accepted
- Date: 2026-10-23

## Context
FR-3.4 (admin action without a role check) and FR-3.3 (IDOR/BOLA, high tier) are heuristics
(PLAN.md §2, §6.4). They must stay under 10% effective FP when shown inline, and they must report
only what a diff introduces.

## Decision
1. **AG-ROLE-001.** Peers are the *other* endpoints of the same router with the same verb class
   (read vs write). For a role atom held by `e` of `n` peers,
   `z = (e/n − 0.9) / sqrt(0.09 / n)`, with `n ≥ 4`. An endpoint lacking an atom with `z ≥ 0` is
   reported, that is, when at least 90% of four or more peers hold it. There is also an absolute
   fallback: a new mutating, authenticated endpoint under an `admin` path with no role check. The
   rule covers new or role-changed AUTH endpoints only, never NO_AUTH ones (AG-AUTH-001) and
   never one AG-AUTH-002 already reports.
2. **Inter-procedural ids.** Summaries record call-site argument names. A request id (a path
   parameter, or a handler parameter named `*_id`/`id`/`uuid`/`pk`) is traced into local callees
   to depth 4 (PLAN.md §6.4). Only values that hold the principal propagate as principals; a
   callee parameter merely *named* `user_id` is not one. Sinks are SQLAlchemy queries,
   `session.get`, model-class ODM calls (Tortoise/Beanie/SQLModel/Django style) and Mongo
   collection calls.
3. **AG-IDOR-001 (heuristic).** An authenticated endpoint without a role or owner guard and
   without an owner comparison, where an id reaches a sink with no principal anywhere in the
   handler or its callees.
4. **AG-IDOR-002 (advisory).** As above, but a principal is available and is neither in the
   predicate nor compared with the object. These go to the LLM judge (ADR 011), which may only
   downgrade or suppress them.
5. Both IDOR rules report new endpoints, or endpoints that did not qualify on the base side,
   and stay silent when AG-AUTH-002 already reports a removed scope or guard.

## Consequences
Statistics need four peers, so small routers rely on the admin-path fallback. Tenancy enforced
outside the handler (row-level security, a per-tenant session) is invisible to IDOR-001/002.
That is why IDOR-001 is heuristic and IDOR-002 advisory until Phase 4's runtime verification
upgrades or refutes a candidate.
