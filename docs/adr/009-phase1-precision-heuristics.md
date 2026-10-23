# ADR 009: Phase 1 precision heuristics for the FastAPI engine

- Status: Accepted
- Date: 2026-10-23

## Context
PLAN.md leaves several Phase 1 behaviours open: how strong evidence must be before a dependency
counts as a guard, which new unauthenticated endpoints deserve an inline comment, and what to do
when the analysis is incomplete. The synthetic mutations pass with almost any choice, so the
choices below were made by replaying the real history of the corpus repos through
`authgraph diff` (`eval/tools/replay_history.py`) and reading every finding. Each rule here
removed a concrete false positive found that way.

## Decision
1. **Guard scoring (FR-7.6, rules only).** A dependency is a guard when it can reject: raises
   401/403 (directly, through a helper, or via an exception object defined in another module),
   or raises 400/404 under an ownership/role predicate. The kind comes from the predicate, not the
   status code (`AUTHZ_OWNER` when it compares the caller with request data or an owner field,
   `AUTHZ_ROLE` for role atoms). Names containing `optional`/`maybe`, and functions that decode a
   token but never reject, are `OPTIONAL_AUTHN`/`FAKE` and never make an endpoint AUTH.
   Confidence below 0.7 never yields AUTH. Known primitives are seeded: `fastapi.security`
   schemes (respecting `auto_error=False`) and fastapi-users `current_user(...)` flags.
2. **UNKNOWN over guessing.** An unresolved dependency whose name looks auth-related, a dynamic
   path, or a flag-selected dependency factory whose branches disagree makes the endpoint
   UNKNOWN. A guard is only reported as *removed* when the head endpoint has no unresolved
   dependencies (the unresolved one may be the guard, e.g. a file that no longer parses).
3. **AG-AUTH-001 tiers.** A new unauthenticated endpoint is reported inline (deterministic,
   high/critical) when it is mutating or under an admin path. A new unauthenticated *read* next to
   authenticated router peers is advisory (check-run summary only): in the replayed histories
   these were public-by-design reads (tiers, public profiles, articles) far more often than bugs.
   Auth-flow endpoints (login, signup, token, password reset, webhooks, health, `/auth/...`) and
   `POST` to a bare user/account collection (the signup convention) are not reported; a role or
   owner field in such a body is still AG-ROLE-002.
4. **Deltas need comparable facts.** `condition_weakened` requires the base and head predicates to
   share at least one atom and the base predicate not to be a tautology (a guard that rejects
   everyone is a modelling artefact). Rejections inside `except` blocks are conditioned on the
   exception; statements after `if x: return` are conditioned on `not x`. `sink_before_check`
   counts only write/delete sinks: fetch-then-check is the normal ownership pattern.
   Principal-scoped sinks are compared as multisets per (kind, model).
5. **Handlers' `except` translations are not guards.** `except PermissionError: raise
   HTTPException(403)` in a handler maps service errors; it is not a check the handler performs.

## Consequences
Precision on the replayed histories is high (see the Phase 1 PR for the per-repo table), at the
cost of some recall: an unauthenticated read next to authenticated peers is only summarised, and
a deliberately public `POST /users` admin action without a role guard is not flagged by
AG-AUTH-001. These trade-offs are revisited with pilot data in Phase 4; per-rule effective-FP
tracking (Phase 2) can promote the advisory tier back to inline if its action rate is high.
