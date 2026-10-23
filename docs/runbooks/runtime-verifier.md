# Runbook: runtime verifier (Phase 4, ADR 015)

The verifier confirms or refutes open findings against a PR's preview deployment. It is off
unless the repository opts in on its base branch, and it never runs repository code.

## Operator: one-time setup
1. Generate the vault key pair:
   ```sh
   uv run accessguard-verifier keygen
   ```
2. Give `ACCESSGUARD_VERIFIER_PUBLIC_KEY` to the `api` process only. Give
   `ACCESSGUARD_VERIFIER_PRIVATE_KEY` to the `verifier` process only:
   - Fly: `fly secrets set` plus a process-scoped secret, or a separate app for the `verifier`
     process.
   - Compose: `.env.verifier`, which only the `verifier` service loads.
3. Start the `verifier` process: `arq accessguard_app.jobs.worker.VerifyWorker`, which reads
   queue `arq:verify`. `ACCESSGUARD_VERIFIER_BUDGET` caps the number of requests per run
   (default 30).
4. Accept the App's new permissions (`deployments: read`, `statuses: read`) and events
   (`deployment_status`, `status`); see `register-github-apps.md`. Each installation must
   approve the updated permission request.

Rotating the key pair makes the stored credentials unreadable. Ask maintainers to upload them
again.

## Maintainer: enable a repository
1. On the default branch, add to `.accessguard.yml`:
   ```yaml
   verifier:
     enabled: true
     preview_hosts: ["*.vercel.app"]   # shell globs; the deployment URL host must match
   ```
2. Create two low-privilege test accounts on the preview environment: `user_a` and `user_b`.
   Never use real users or admins.
3. Upload their credentials. This needs a GitHub user token with write access to the repository:
   ```sh
   curl -X POST https://<app-host>/verifier/credentials \
     -H "Authorization: Bearer $GITHUB_USER_TOKEN" -H 'content-type: application/json' \
     -d '{"repo":"acme/app","label":"user_a","credential":{"type":"bearer","token":"..."}}'
   ```
   - `type` is one of the following:
     - `bearer`: `token`.
     - `cookie`: `cookie`.
     - `headers`: a `headers` map of up to 10 entries.
     - `bypass`: `token`, sent as `x-vercel-protection-bypass`. Use it with label
       `vercel_bypass` for protected previews.
   - The response is `204` with no body. Values are sealed at once and never returned.
4. Remove a credential:
   ```sh
   curl -X DELETE 'https://<app-host>/verifier/credentials?repo=acme/app&label=user_a' \
     -H "Authorization: Bearer $GITHUB_USER_TOKEN"
   ```

## What a run does
When a preview succeeds for a PR head that has a finished scan, the job checks the PR and the
config, generates tools for the flagged endpoints, and runs a template plan:
- an anonymous call for missing authentication;
- `user_b` for missing role checks;
- for IDOR: `user_a` creates a marked fixture, `user_b` reads it, then `user_a` deletes it.

Every call is listed in `verifier_audit`, with URLs only and no secrets. Results appear in the
`AccessGuard / runtime` check run. A finding in the `verified` tier means a 2xx response was
observed, not a model's opinion.

## Troubleshooting
| Job result | Cause |
|---|---|
| `skipped: verifier key not configured in this process` | The private key is missing from the `verifier` process. |
| `skipped: verifier.enabled is false on the base branch` | Opt-in is missing on the base branch. A change on the PR head does not count. |
| `skipped: preview host is not in verifier.preview_hosts` | The host glob does not match the deployment URL. |
| all targets `inconclusive` | Credentials for `user_a`/`user_b` are missing, the preview returns 5xx, or there is no safe plan (a write to an object we did not create). |
| `refused: ... non-public address` | The preview host resolved to a private or metadata IP. This is refused by design. |
