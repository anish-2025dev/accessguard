# ADR 018: Admin/super-user settings comparisons are role checks

- Status: Accepted
- Date: 2026-10-24

## Context
The Phase 4 pilot/corpus replay recorded AG-ROLE-001 over-firing on lnbits (ADR 017, PR #5's
"known limitations"): five admin endpoints guarded by `Depends(check_admin)` /
`Depends(check_super_user)` were flagged as "admin-path write with no role check."

Those guards reject with `HTTP 403` when the principal is not an admin, comparing
`account.id == settings.super_user` or `account.id in settings.lnbits_admin_users`. The scorer
(`guards/scoring.py`) read the `account.id == …` shape as an ownership comparison
(`owner_compare`) and, because `_ROLE_ATOM` uses `\b` word boundaries, missed the role signal
(`admin` is underscore-delimited inside `lnbits_admin_users`; `super_user` is not `superuser`).
So the guards were classified `AUTHZ_OWNER`, not `AUTHZ_ROLE`, and the endpoints looked
role-less.

## Decision
A guard whose rejection condition compares the principal against an admin/super-user reference in
application **settings or config** is a privilege (role) check, not per-object ownership. In
`classify`, before the ownership-shape branch, a new `_ADMIN_SETTING` pattern
(`(settings|config|conf|cfg|app_settings).<…>(super_?user|admin|staff|root)`) routes such a guard
to `GuardKind.AUTHZ_ROLE`.

This is deliberately narrow: it keys on a comparison against a settings/config admin reference,
which a genuine owner check (`resource.owner_id == current_user.id`, comparing a resource to the
request principal) never has. Negative fixture `m62_admin_settings_role_guard`; `make eval` stays
62/62 and the full suite 166 passing.

## Consequences
- Four of the five lnbits false positives disappear (`check_admin` / `check_super_user` guards:
  `/admin/api/v1/onchain/key`, `/key/backup`, `/key/confirm`, `/users/.../admin`).
- The fifth, `GET /api/v1/onchain/hot-wallet/status`, is out of scope: its guard
  `require_onchain_admin` raises 403 on `not info.wallet.is_onchain_wallet` — a wallet-capability
  check after an admin-API-key dependency, not a settings-admin comparison. Recognising
  capability/key guards as role checks is a separate, broader change left for later.
- ENGINE_VERSION 29 (finding logic changed; summary cache invalidated).
