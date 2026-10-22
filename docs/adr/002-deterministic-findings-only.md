# ADR 002: The deterministic engine is the only source of findings

- Status: Accepted
- Date: 2026-10-23

## Context
Unaided LLM agents produced 82-86% false positives on Python web apps and different results on repeated runs (Semgrep study, 2025). They scored 0% on IDORs where checks are spread across files or in middleware. LLMs judge well when given precise evidence (ZeroFalse F1 0.91-0.96).

## Decision
Findings come only from deterministic rules over the fact graph. The LLM may:
- downgrade or suppress a finding, with a logged reason shown in the check summary;
- classify candidate auth guards (FR-7.6);
- judge medium-tier IDOR candidates;
- write explanations and fix suggestions.

LLM calls are tool-less, get no secrets, use temperature 0 and a JSON schema.

## Consequences
A successful prompt injection can at worst suppress one finding, visibly. Recall is bounded by the engine, so the engine must be good.
