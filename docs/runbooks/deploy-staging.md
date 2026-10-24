# Runbook: local development and staging

## Local (docker compose)

1. Register the dev App (`docs/runbooks/register-github-apps.md`); this writes `.env.dev`.
2. `docker compose -f deploy/docker-compose.yml up --build` starts Postgres 16, Redis 7, runs
   `alembic upgrade head`, then the API (`:8000`) and both workers (high and low queues).
3. Forward webhooks: `npx smee-client --url <smee channel> --target http://localhost:8000/webhooks/github`.
4. Install the dev App on a test repository and open a PR. The check run "AccessGuard" appears
   on the head commit; findings are inline review comments.

## Staging (Fly.io)

1. Register the `accessguard` (prod manifest) or a separate `accessguard-staging` App with the
   staging domain in `hook_attributes.url`, `callback_urls` and `setup_url`.
2. `fly launch --no-deploy --config deploy/fly.toml` once, attach managed Postgres and Redis
   (they set `DATABASE_URL` / `REDIS_URL`; use the `postgresql+asyncpg://` scheme).
3. `fly secrets set GITHUB_APP_ID=... GITHUB_APP_SLUG=... GITHUB_CLIENT_ID=... GITHUB_CLIENT_SECRET=...
   GITHUB_WEBHOOK_SECRET=... GITHUB_PRIVATE_KEY="$(cat app.pem)" PUBLIC_URL=https://<domain>`.
4. Deploy from the repo root: `fly deploy . --config deploy/fly.toml --dockerfile deploy/Dockerfile`
   (the release command runs `alembic upgrade head`).
5. Health: `GET /healthz` (process), `GET /readyz` (Postgres + Redis), `GET /metrics`.

## Exit-gate checks (PLAN.md §3 Phase 2)

- **Scripted E2E:** with the staging App installed on a throwaway repo,
  `GH_E2E_TOKEN=<PAT> uv run python deploy/e2e/staging_e2e.py <owner>/<repo>` pushes every eval
  mutation case as a PR and checks the reported rules and the p95 latency (< 120 s).
- **No lost webhooks:** stop the API for 10 minutes (`fly scale count api=0`), open and update
  PRs, start it again. `reconcile_deliveries` (every 15 min) redelivers the failed deliveries;
  `SELECT count(*) FROM webhook_deliveries WHERE status <> 'routed'` must reach 0 and every PR
  must have its check run. The same scenario runs in CI against a fake GitHub
  (`test_server_down_loses_no_webhooks`).

## Operations

- Rotate the webhook secret: set the new value in the App settings and `fly secrets set` in the
  same window; deliveries signed with the old secret during the gap are redelivered by the
  reconciler once they fail.
- An installation whose token mint returns 401/404 is paused (fail closed); the hourly
  `reconcile_state` re-activates it if GitHub still lists it.
