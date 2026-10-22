# ADR 007: No web frontend

- Status: Accepted
- Date: 2026-10-23

## Context
The value is in the engine's accuracy. GitHub already provides the surfaces developers use: check runs, PR review comments, issues.

## Decision
The interface is GitHub (check runs, inline comments, summary), the `authgraph` CLI, and `.accessguard.yml`. The API serves only webhooks, the install/OAuth callback (a plain confirmation page), health and metrics.

## Consequences
No dashboard for history or trends; revisit only if pilot users ask for it.
