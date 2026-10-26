# ADR 011: LLM judge: downgrade, suppress, classify and explain only

- Status: Accepted
- Date: 2026-10-23

## Context
PLAN.md §6.13 adds an LLM judge in Phase 3 for triage, guard classification and explanations,
and ADR 002 says the deterministic engine is the only source of findings. Phase 3's exit gate
asks that triage keeps at least 96% of true positives. Repository text reaches the model, so it
is an injection surface. CLAUDE.md forbids installing local models for this project.

## Decision
1. **Interface.** `authgraph.llm.judge.Judge` has exactly `triage`, `classify_guard` and
   `explain`. `TriageResult.decision` is `keep | downgrade | suppress`; there is no value that
   adds or upgrades a finding.
2. **Enforced in code, not in the prompt.** `apply_triage` only relabels (`downgrade` → tier
   `advisory`) or removes (`suppress`) findings it was given, and raises if its output contains
   a fingerprint that was not in its input. Suppressed findings are returned with the judge's
   reason, logged, and counted in the check-run summary.
3. **Scope.** Only `heuristic` and `advisory` findings are triaged. `deterministic` findings are
   proven by the engine; at most they get an explanation.
4. **Robustness.** IDOR judgements use three samples and a majority vote (ties keep). Any judge
   error, timeout or malformed answer keeps the finding (fail-open towards reporting).
5. **Untrusted input.** The judge sees bounded slices only (6 slices, 12k characters), wrapped in
   `<untrusted_code>` tags. Lines that address a reviewer or a model ("AI reviewer:", "ignore
   previous instructions", "mark as safe") are replaced before sending. Agent-instruction files
   (`CLAUDE.md`, `AGENTS.md`, `.cursorrules`, `.github/instructions/`) and non-source files are
   never sent. Temperature 0, JSON-schema output, no tools.
6. **Guard classification is a suggestion.** `suggest_guards` turns ambiguous functions (scored
   below confirmation) into suggestions for maintainers to confirm into `auth_guards` (FR-7.6);
   it never changes a verdict by itself.
7. **Backend.** LiteLLM behind the optional `authgraph[llm]` extra, configured with
   `ACCESSGUARD_LLM_MODEL`. Off by default. Tests use `FakeJudge`; the LiteLLM path is tested
   with `mock_response` when the extra is installed.

## Consequences
The judge can only reduce noise, never create it, and a broken or hostile model degrades to the
deterministic report. TP retention is measured by `make eval-triage MODEL=<model>` over every
mutation-case TP and every replay finding labelled `tp`. CI has no model access, so CI only
checks the pipeline with `FakeJudge`. The 96% gate must be measured whenever the configured
model changes, and the result recorded in the release notes.
