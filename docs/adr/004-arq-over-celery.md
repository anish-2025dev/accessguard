# ADR 004: ARQ (on Redis) over Celery for background jobs

- Status: Accepted
- Date: 2026-10-23

## Context
The API is async FastAPI. Scans must be deduplicated and cancellable when a newer commit arrives on the same PR.

## Decision
Use ARQ: asyncio-native, `_job_id` prevents duplicate enqueues, `_defer_by` for debouncing, `Job.abort()` with `allow_abort_jobs=True` for best-effort cancellation. Cancellation is cooperative: jobs check a per-PR generation counter between phases and before posting. Celery's `revoke` cannot safely stop running tasks (`terminate=True` is discouraged by its docs).

## Consequences
ARQ may run a job more than once, so every job must be idempotent on its work key `(repo_id, head_sha, trigger, config_hash)`.
