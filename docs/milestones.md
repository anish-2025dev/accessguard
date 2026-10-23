# Milestones

One GitHub milestone per phase (PLAN.md §3); every issue carries its FR / rule ID and milestone.
Each phase is delivered as one pull request on a stacked branch.

| Milestone | Branch | Builds | Exit gate | Status |
| --- | --- | --- | --- | --- |
| Phase 0: Foundations | `phase-0-foundations-*` | Repo, CI, ADR 001-008, App manifests, eval corpus skeleton, route-truth sandbox | `make eval` runs in CI and reports per-rule numbers | In review |
| Phase 1: Engine core (FastAPI) | `phase-1-engine-*` | FR-3.1, 3.2, 3.5, 3.6, 7.6 (rules); AG-AUTH-001/002/003, AG-ROLE-002, AG-CFG-001; CLI JSON/SARIF | Route recall >= 95%, mutation recall >= 95%, precision >= 90%, 0 pure-move findings | Planned |
| Phase 2: GitHub App delivery | `phase-2-github-app-*` | FR-1.1-1.6, FR-2.1-2.4, FR-2.6, reporter, feedback | E2E on staging, p95 < 2 min, zero lost webhooks | Planned |
| Phase 3: Breadth and data layer | `phase-3-breadth-*` | Express, FR-3.4, FR-3.3 high tier, LLM judge, FR-3.8/3.9/3.10 | Every rule measured, none > 10% effective FP | Planned |
| Phase 4: Runtime verification | `phase-4-runtime-*` | FR-2.5, RV-1-4, FR-3.8b, IDOR verified tier, pilot | v1.0 with published precision table | Planned |

Creating the milestones on GitHub is a one-time manual step (Issues → Milestones → New), using
the names in the first column.
