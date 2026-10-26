# Runbook: register the dev and prod GitHub Apps

PLAN.md §4 asks for two registrations: `accessguard-dev` (webhooks through smee.io to a laptop)
and `accessguard` (production). Both are created from checked-in manifests so their permissions
are reviewed in git. A human with owner rights on the target account must click through; the
automation cannot do this step.

Manifests: `deploy/github-app/manifest.dev.json`, `deploy/github-app/manifest.prod.json`.

| Setting | Value | Source |
| --- | --- | --- |
| Permissions | `contents: read`, `pull_requests: write`, `checks: write`, `issues: write`, `metadata: read` | PLAN.md §5 security model |
| Events | `pull_request`, `push`, `issue_comment`, `check_run` (`installation` and `installation_repositories` are delivered to every App automatically) | [webhook events](https://docs.github.com/en/webhooks/webhook-events-and-payloads) |
| OAuth on install | `request_oauth_on_install: false`, `setup_url: /connect`: after installing, users sign in through `/connect`, which carries our own state + PKCE (ADR 010) | [manifest parameters](https://docs.github.com/en/apps/sharing-github-apps/registering-a-github-app-from-a-manifest#github-app-manifest-parameters) |

Phase 4 (runtime verification) will add `deployment_status` / `status` events with
`deployments: read` and `statuses: read`; that change gets its own ADR and manifest diff.

## Dev app

1. Create a smee channel at <https://smee.io/new> and put its URL in
   `manifest.dev.json` → `hook_attributes.url`.
2. `uv run python deploy/github-app/register.py form dev` (add `--org <org>` for an org).
3. Open the generated `deploy/github-app/register-dev.html`, press **Register on GitHub**, keep
   the name `accessguard-dev`, and confirm.
4. GitHub redirects to `http://localhost:8000/manifest/redirect?code=...&state=...`. The page will
   not load (nothing listens yet); copy `code` from the address bar and check `state` matches the
   value shown on the form page.
5. Within one hour: `uv run python deploy/github-app/register.py convert <code> --env-file .env.dev`.
   This writes `.env.dev` and `.env.dev.pem` (both gitignored, mode 600).
6. Install the app on a test repository from the app's settings page.

## Prod app

1. Replace `REPLACE-WITH-DOMAIN` in `manifest.prod.json` (`public: true`).
2. `uv run python deploy/github-app/register.py form prod` (add `--org <org>` for an org).
3. Open `deploy/github-app/register-prod.html`, register `accessguard`, and copy the redirect
   code after checking the state as described above.
4. Within one hour: `uv run python deploy/github-app/register.py convert <code> --env-file .env.prod`.
   This writes `.env.prod` and `.env.prod.pem` (both gitignored, mode 600), separately from dev.
5. Move the production values and private key into the hosting platform's secret store and delete
   the local production copies. The private key must never be committed (`*.pem` is gitignored).

## Rotating secrets

Webhook secret and private keys are rotated from the app's settings page; update the platform
secret store, deploy, then revoke the old key.
