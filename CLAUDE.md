# AccessGuard

GitHub App (installed like CodeRabbit) that reports access-control regressions in PRs and pushes to main:
"who can access what, and did this change make it worse?" Full spec: @docs/PLAN.md. Decisions: `docs/adr/`.

Current phase: **Phase 2 (GitHub App delivery)**. Don't build features from later phases unless asked.

## Layout
- `packages/authgraph` - analysis engine + CLI. The ONLY component that produces findings.
- `packages/app` - GitHub App (webhooks, jobs, reporter). Delivery only, no analysis logic.
- `packages/sandbox`, `packages/verifier` - Phase 3/4.
- `eval/` - labelled corpus, synthetic PR mutations, harness.

## Commands (uv workspace, Python 3.12)
- Install: `uv sync`
- Test: `uv run pytest -q` (single test: `uv run pytest -q path::test_name`)
- Lint/types: `uv run ruff check . && uv run mypy packages/authgraph`
- Eval (must not regress): `make eval`

## Architecture rules (do not violate; see ADRs)
- The deterministic engine is the only source of findings. The LLM may only downgrade/suppress (with a logged reason), classify guards, or explain. Never let it add findings.
- Never import, install or execute code from scanned repos. Parse with Python `ast` / tree-sitter only. Migrations run only in the network-less sandbox.
- `authgraph` must not import from `app` or `verifier`.
- `.accessguard.yml` is read from the PR's base branch, never the head.
- Every webhook job is idempotent (delivery GUID + work key). Workers re-fetch live PR state; never trust payload order.
- Report only findings introduced by the diff. Verdicts are three-valued: AUTH / NO_AUTH / UNKNOWN; never report UNKNOWN as a finding.
- No frontend. Interface = GitHub check runs + PR comments + CLI.
- Out of scope: rate-limit detection, hallucinated-package checks, general code-quality/style comments.

## Accuracy rules
- IMPORTANT: Never write GitHub API endpoints/payload fields, githubkit methods, or any library API from memory. Verify first: read the installed package source (`uv run python -c "import inspect, githubkit; ..."`) or the official docs, and cite the doc URL in the PR description.
- If something in PLAN.md is ambiguous or seems wrong, stop and ask instead of guessing.
- A new rule is not done until it has a positive and a negative fixture in `eval/` and `make eval` shows its precision/recall.
- Show evidence (command + output) for tests and eval results; don't just say they pass.

## Conventions
- Conventional Commits (`feat:`, `fix:`, `docs:`, `test:`, `chore:`). Short-lived branches, squash merge to `main`.
- Reference the requirement ID (e.g. FR-3.2, AG-AUTH-002) in commit messages and PR titles.
- `mypy --strict` for `packages/authgraph`; Pydantic models for the fact model (PLAN.md §6.2).

## When compacting
Preserve: current phase, list of modified files, failing test names, and any unresolved questions for the user.
