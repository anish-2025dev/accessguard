# ADR 016: Supabase proof probes (SET ROLE in the sandbox)

- Status: Accepted
- Date: 2026-10-23

## Context
FR-3.8b requires a data-layer exposure to be shown against a real database: `SET ROLE anon`,
then attempt SELECT and INSERT on the exposed tables. This must happen in the same network-less
sandbox that replays the migrations (ADR 005, ADR 013). The exposure is not just inferred from
the catalog.

## Decision
1. **Where.** `PostgresSandbox.replay(tree, probe=True)` runs the probes in the same disposable
   container, after the catalog has been read. The CLI option is
   `accessguard-sandbox supabase <src> --probe`. `claims=` additionally probes exposures from
   another source, for example the static engine's own, so that a static exposure the database
   does not confirm is visible.
2. **How.** Each (relation, role, op) gets one transaction, which is always rolled back:
   - The superuser seeds a row with `session_replication_role = replica`, which turns off
     foreign-key triggers. Values are filled for NOT NULL columns without a default: a fixed
     literal per type category, the first label for enums, and `gen_random_uuid()` for UUIDs.
   - `SET LOCAL ROLE anon|authenticated`. For `authenticated`, `request.jwt.claims` gets a fresh
     `sub`, which is not the seeded owner.
   - **select**: the probe is `proven` when the seeded row is visible. It is `denied` on 42501
     or when the row is filtered out.
   - **insert**: the probe is `proven` when the insert succeeds or fails only with SQLSTATE
     class 23 (data constraint). It is `denied` on 42501.
   - Anything else is `inconclusive`: an insert through a view, a column type with no probe
     value, a failed seed, or another SQLSTATE.
3. **Verified behaviour.** The probes rely on the following, checked empirically on
   `postgres:16`:
   - Privileges and the RLS `WITH CHECK` are evaluated before NOT NULL. A table with
     `with check (false)` and a missing NOT NULL value returns 42501, not 23502.
   - `session_replication_role` survives `SET LOCAL ROLE`.
   - `anon` cannot set `session_replication_role` itself (42501).
4. **Scope.** Only SELECT and INSERT are probed, as FR-3.8b specifies. UPDATE and DELETE
   exposures (`policy_true_write` on update, for example) remain static findings.
5. **Delivery.** Probes do not run in the App's scan workers, which never start containers
   (ADR 005, ADR 010). They run in the sandbox CLI, the eval and the differential test suite.
   Marking App findings as `verified` from probes needs a sandbox runner service. That is
   deferred until a deployment with an isolated Docker host exists.

## Consequences
- Every SELECT/INSERT exposure in the Supabase eval fixtures is proven, and an owner-scoped
  table is denied for both roles (`sandbox_tests/test_supabase_sandbox.py`).
- Probes add one `psql` round trip per (relation, role, op). The cost is bounded by the number
  of exposures, which are few per repository.
