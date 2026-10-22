# ADR 008: Runtime-verification MCP tools are generated from facts, never written by an LLM

- Status: Accepted
- Date: 2026-10-23

## Context
Phase 4 verifies findings against preview deployments using test-account credentials. Repo content may contain prompt injection; an LLM that writes tool code could be steered to exfiltrate credentials.

## Decision
The MCP broker generates tools from engine route facts using fixed templates (`call_as(identity, method, path, ...)`). Credentials live in an envelope-encrypted vault and are injected by the broker at call time; the LLM never sees them. A policy layer enforces preview-host allowlists, private-IP blocking, read-only by default, call budgets, response redaction and an audit log. Pass/fail is decided by deterministic response comparison; the LLM only plans test sequences.

## Consequences
New verification capabilities require new templates (a code change), not prompts.
