# Contributing to AccessGuard

AccessGuard answers one question: **who can access what, and did this change make it worse?**
Features that don't answer it are out of scope (see `docs/PLAN.md` §1 non-goals).

## Setup

```bash
uv sync                      # Python 3.12, one lockfile for the whole workspace
uv run pre-commit install    # ruff, ruff format, mypy --strict on authgraph
make check                   # lint + types + tests
make eval                    # per-rule precision/recall on the labelled corpus
```

## Workflow

- Trunk-based: short-lived branches off `main`, squash merge.
- Conventional Commits (`feat:`, `fix:`, `docs:`, `test:`, `chore:`) with the requirement ID,
  e.g. `feat(authgraph): FastAPI include_router prefixes (FR-3.1)`.
- Architecture changes need an ADR in `docs/adr/` (copy the format of an existing one).

## Rules that block a merge

1. CI is green: ruff, `mypy --strict` on `packages/authgraph`, pytest.
2. **Eval gate:** no rule's precision or recall drops versus `main` (`make eval BASELINE=...`).
3. **A new rule is not done** until it has at least one positive and one negative case under
   `eval/mutations/` (or `eval/pairs/`) and its numbers appear in the eval report.
4. The deterministic engine is the only source of findings. LLM code may only downgrade or
   suppress (with a logged reason), classify guards, or explain (ADR 002).
5. Never import, install or execute code from scanned repositories outside the network-less
   sandbox (ADR 005). Parse with `ast` / tree-sitter.
6. `authgraph` never imports from the GitHub App or the verifier (enforced by a test).
7. Library and GitHub API usage is verified against installed source or official docs, and the
   doc URL is cited in the PR description.

## Adding an eval case

```
eval/mutations/mNN_short_name/
  base/...         # repository before the PR
  head/...         # repository after the PR
  case.yaml        # id, kind (positive | negative | move), expected: [{rule_id, key}]
```

`key` is the endpoint id (`"METHOD /normalized/path"`) or the resource for data-layer rules.
`kind: move` cases must produce zero findings.
