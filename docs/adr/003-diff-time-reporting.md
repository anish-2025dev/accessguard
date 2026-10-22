# ADR 003: Report only findings introduced by the diff

- Status: Accepted
- Date: 2026-10-23

## Context
Facebook's Infer saw over 70% of findings fixed when reported at diff time, versus near zero for the same analysis as batch reports. Google disables analyzers whose "not useful" rate exceeds 10%.

## Decision
Build fact graphs for base and head; report only new findings on changed routes. Fingerprints exclude line numbers so moved code doesn't resurface. Three-valued verdicts (AUTH / NO_AUTH / UNKNOWN); UNKNOWN is never reported as a finding. Track per-rule effective false-positive rate and auto-demote rules above 10%.

## Consequences
Pre-existing issues aren't flagged on PRs (baseline scan records them separately). Requires fast base+head analysis, handled by the blob-SHA summary cache.
