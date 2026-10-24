# ADR 010: Delivery pipeline: outbox, work keys, generations, install linking

- Status: Accepted
- Date: 2026-10-23

## Context
Phase 2 must lose no webhook, never post twice for the same finding, never report on a stale
head, and link GitHub users to installations without trusting a client-supplied
`installation_id` (PLAN.md FR-1.1, FR-1.3, FR-2.6, §6.12). PLAN.md fixes the components
(Postgres outbox, ARQ, Redis generation keys) but not every mechanism.

## Decision
1. **Outbox first.** `POST /webhooks/github` verifies HMAC-SHA256 on the raw body (SHA-1 headers
   are rejected even though githubkit's `verify` would accept them), inserts the delivery with
   `ON CONFLICT DO NOTHING` (duplicate GUID -> 200, no work), then enqueues `route_delivery` with
   job id `delivery:{guid}`. If Redis is down the request still returns 202; `outbox_sweeper`
   re-enqueues anything left in `received` for over a minute. Deliveries GitHub could not make
   while we were down are redelivered by `reconcile_deliveries` (15 min) unless a later attempt
   already reached us.
2. **Payloads are triggers.** The router re-fetches the live PR (head SHA, draft, state) and
   re-lists installation repositories; it never trusts payload contents or ordering.
3. **Work keys and generations.** Jobs are keyed (`scan:{repo}:{pr}:{head}`, `push:{repo}:{after}`,
   `baseline:{repo}:{ref}`) so ARQ drops duplicates. Each scheduling bumps
   `pr:{repo}:{n}:gen`; `scan_pr` re-checks it after fetching, after analysis and before
   reporting, and cancels its check run (`cancelled`) when superseded. A scan row is unique per
   (repo, head, trigger, config hash) and a finished identical scan is reused.
4. **Reporter upserts by fingerprint.** Findings are stored per (repo, PR, fingerprint) with the
   review-comment id; a re-scan edits the existing comment, and a fingerprint missing from the
   new head marks the finding resolved and rewrites its comment ("✅ Resolved in …"). Inline
   comments are posted only for deterministic-tier findings; a rejected line (not in the diff)
   falls back to the check-run summary. Rules above 10% effective FP over 90 days (n >= 20) are
   shown as advisory (auto-demotion).
5. **Install linking with state + PKCE.** GitHub's install-time OAuth redirect carries only
   `client_id`, so our state and PKCE would not survive it. `/connect` therefore always starts a
   sign-in with a single-use server-side `state` and an S256 PKCE challenge; `/callback`
   consumes the state atomically (`DELETE ... RETURNING`), exchanges the code with the
   `code_verifier` (a direct `POST /login/oauth/access_token`, since githubkit's web flow has no
   PKCE parameter) and links only installations returned by `GET /user/installations`. The
   manifests set `request_oauth_on_install: false` and `setup_url: /connect`.
6. **Schema deltas from PLAN.md §6.7.** `feedback` gets a surrogate `id` primary key, and
   `findings` gets `pr_number` so PR comment threads are upserted per PR. Everything else matches
   §6.7; migrations are Alembic (`packages/app/src/accessguard_app/db/migrations`).
7. **Commands.** `@accessguard scan` / `@accessguard ignore <id> <reason>` require write,
   maintain or admin permission (checked live), ignore bot senders, and are rate-limited per PR
   (5/min) and per user (30/h). `# accessguard-ignore[RULE]` above a route suppresses in code.

## Consequences
At-least-once processing with idempotent jobs: every job may run twice without double posting.
The cost is an extra GitHub read per event (live PR fetch) and an extra sign-in step for users
who install first; both are cheap compared with acting on stale or forged state.
