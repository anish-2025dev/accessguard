# AccessGuard

A GitHub App that reviews pull requests and pushes for **access-control regressions** in AI-written backends: routes that lost their auth, admin actions without role checks, missing ownership checks, Supabase tables left open, and secret keys shipped to the browser.

It answers one question on every change: **who can access what, and did this change make it worse?**

> Status: Phase 2 (GitHub App delivery). The `authgraph` CLI works on FastAPI apps; the App runs locally with docker compose (see docs/runbooks/deploy-staging.md).

## How it works
A deterministic engine (`authgraph`) builds a fact graph of every route, the auth guards that apply to it (including ones inherited from routers and middleware) and the data it touches, for both the PR's base and head. It reports only what got worse. An LLM may explain or downgrade findings, never create them.

- Spec, roadmap, HLD and LLD: [docs/PLAN.md](docs/PLAN.md)
- Architecture decisions: [docs/adr/](docs/adr/)

## Planned support
- Code: FastAPI (first), Express
- Data: Supabase migrations (RLS, policies, grants), Firebase security rules
- Delivery: GitHub check runs and PR review comments, plus a CLI (`authgraph scan`, `authgraph diff`)

## Development
```bash
uv sync && uv run pre-commit install
make check        # ruff, mypy --strict (authgraph), pytest
make eval         # per-rule precision/recall on eval/ (synthetic mutations + corpus)
```
See [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md) and [docs/privacy.md](docs/privacy.md).
Licensed under Apache-2.0.

## Development with Claude Code
This repo ships Claude Code configuration in `CLAUDE.md` and `.claude/`:
- `CLAUDE.md`: project rules and commands, loaded every session
- `.claude/settings.json`: hooks that format edited Python files and block finishing while lint/types/tests fail (requires `jq` and `uv`)
- `/add-rule <RULE-ID>`: workflow for adding a detection rule with eval fixtures
- `plan-reviewer` subagent: reviews a diff against the plan and ADRs
