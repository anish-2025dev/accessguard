# ADR 015: Runtime verifier: preview intake, sealed credentials, broker policy

- Status: Accepted
- Date: 2026-10-23

## Context
Phase 4 (FR-2.5, RV-1..4, PLAN.md §6.14) confirms static findings against a PR's preview
deployment. The verifier then holds test-account credentials and sends HTTP requests to a host
that a webhook names. Both are new risks. It must never run repository code, never reach
internal networks, and never let a model decide an outcome or add a finding (ADR 002).

## Decision
1. **Preview intake.** We use the `deployment_status` webhook (state `success`,
   `environment_url`) and, as a fallback for providers that only post commit statuses, the
   `status` webhook (state `success`, `target_url`). The App gains the `deployments: read` and
   `statuses: read` permissions. The SHA is mapped to open PRs with "list pull requests
   associated with a commit". The preview URL is stored in Redis as `preview:{repo}:{sha}`. If
   the scan for that head is not finished yet, the scan job enqueues verification when it
   completes. Otherwise the router enqueues `verify_findings` directly. The job id is
   `verify:{scan_id}`, so a redelivered event is a no-op.
2. **Opt-in from the base branch.** Verification runs only when the base-branch
   `.accessguard.yml` sets `verifier.enabled: true`. The preview host must also match
   `verifier.preview_hosts` (shell globs). The job re-fetches the PR and skips if the head moved
   or the PR closed.
3. **Process separation, X25519 sealing.** Credentials are uploaded via
   `POST /verifier/credentials` with a GitHub user token that has write permission on the repo.
   The API seals each one with the vault's **public** key: an ephemeral X25519 key, HKDF-SHA256
   and AES-GCM, with `(repo_id, label)` as associated data. Only the `VerifyWorker` process
   (`arq:verify`) receives `ACCESSGUARD_VERIFIER_PRIVATE_KEY`. A compromised API or scan worker
   therefore cannot decrypt stored credentials. Opened credentials refuse `repr` and pickling.
   Their values are masked in every observation. Responses never echo inputs. The key pair comes
   from `accessguard-verifier keygen`.
4. **Broker policy.** Every request goes through the broker. The broker enforces these rules:
   - HTTPS only.
   - The host must be exactly the preview host.
   - No userinfo in the URL.
   - Every resolved address must satisfy `ipaddress.ip_address(...).is_global`. This blocks
     RFC 1918, loopback, link-local and metadata addresses, CGNAT, ULA, and v4-mapped private
     addresses.
   - The connection is pinned to the checked IP, with the original `Host` header and SNI. This
     closes the DNS-rebinding window.
   - Only GET/HEAD on flagged endpoints are allowed. The exceptions are `create_fixture` on the
     collection endpoint and DELETE of fixtures this run created.
   - A per-run request budget applies (`verifier_budget`).

   Every call, including refused ones, is written to `verifier_audit`, with redacted URLs only.
5. **Templates decide; models never do.** Tools are generated from findings (ADR 008). The
   default planner is template-based. An optional LLM planner's plan is validated against the
   generated schemas before it runs. The outcome is decided by comparing responses:
   - The attacker gets 2xx (plus the fixture marker for IDOR reads): `verified`.
   - The attacker gets 401/403/404: `refuted`.
   - Anything else: `inconclusive`.

   A `verified` finding moves to tier `verified`. A `refuted` one only gets an evidence step.
   Suppressing it stays a human decision. Results go to a separate
   `AccessGuard / runtime` check run, so the static check keeps its meaning.

## Consequences
- Maintainers must create two low-privilege test accounts (`user_a`, `user_b`) on the preview.
  If the preview is protected, they also add an optional bypass token. Without them, every
  target is `inconclusive`, never a finding.
- Endpoints that would need a write to an object we did not create are never attacked
  (`inconclusive: no safe plan`).
- The new permissions require existing installations to accept an updated permission request.
  Until they do, no deployment events arrive and nothing else changes.
