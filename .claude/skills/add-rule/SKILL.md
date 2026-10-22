---
name: add-rule
description: Add a new AccessGuard detection rule (e.g. AG-AUTH-003) with eval fixtures and measured precision/recall
disable-model-invocation: true
---
Add rule $ARGUMENTS.

1. Read docs/PLAN.md §6.2 (fact model), §6.4 (algorithms) and §6.5 (rule table) and find this rule's definition and tier. If it isn't defined there, stop and ask.
2. Read 1-2 existing rules in `packages/authgraph/rules/` and follow their pattern.
3. Write fixtures FIRST in `eval/`:
   - a positive case (base + head) where the rule must fire,
   - a negative case where it must stay quiet (e.g. auth inherited from a router, intentionally public route),
   - a pure code-move case that must produce zero new findings.
   Confirm the positive test fails before implementing.
4. Implement the rule against the fact model only (`FactGraph` in, `Finding` out). No direct source parsing inside rules.
5. Every finding needs an evidence chain and a stable fingerprint (PLAN.md §6.6; no line numbers in the fingerprint).
6. Run `uv run pytest -q` and `make eval`. Report the rule's precision/recall and confirm no other rule regressed. Paste the output.
7. Commit as `feat(rules): <RULE-ID> <short title>`.
