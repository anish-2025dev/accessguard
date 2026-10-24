# Privacy policy (draft for v1.0)

AccessGuard reads your code to answer one question, and keeps as little as possible.

## What we access

With the GitHub App permissions you grant (contents read, pull requests write, checks write,
issues write, metadata read) AccessGuard fetches the files needed to scan a pull request or a
push to the default branch.

## What we store

| Data | Kept | Why |
| --- | --- | --- |
| Source code | **Never stored.** Held in memory / a temporary directory for the duration of one scan, then deleted. | Analysis |
| Per-file summaries (route and guard facts, no source text) | Cache keyed by git blob SHA, expires after 30 days | Fast re-scans |
| Installation and repository metadata (ids, names, default branch, detected stack) | While installed; deleted on uninstall | Delivery |
| Findings (rule id, file path, line, evidence chain, fingerprint) | 90 days after the scan, then archived | Update / resolve PR comments |
| Webhook delivery payloads | 30 days | Idempotency and recovery |
| Feedback (👎, `@accessguard ignore` reasons) | While installed | Measuring false-positive rates |
| Runtime-verifier test credentials (Phase 4, opt-in) | Envelope-encrypted until you delete them | Verifying findings against previews |

## LLM use

The LLM is off by default, in the CLI and in the App. The App sends nothing to a model unless
the repository opts in with `llm.provider: api` (or `ollama`) in `.accessguard.yml` on its base
branch **and** the operator has configured a model (`ACCESSGUARD_LLM_MODEL`; an `ollama/...`
model keeps code on your own infrastructure). When enabled, the judge receives a bounded context
pack (the finding plus at most six code slices), with lines addressed to reviewers or models
removed, and never secrets, images or agent-instruction files (`CLAUDE.md`, `AGENTS.md`, ...).
It can only keep, downgrade or suppress heuristic and advisory findings (ADR 011).

## Deletion

Uninstalling the App deletes installation data within 24 hours (findings within 30 days).
Questions or deletion requests: open a private report via the repository's Security tab.
