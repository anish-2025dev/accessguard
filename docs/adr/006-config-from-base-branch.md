# ADR 006: Read `.accessguard.yml` from the base branch only

- Status: Accepted
- Date: 2026-10-23

## Context
The config declares custom auth guards and intentionally public routes. A PR could otherwise declare its own no-op function a guard, or allowlist the route it just opened up.

## Decision
Load config from the PR's base branch. Any PR that edits `auth_guards` or `public_routes` produces finding AG-CFG-001 so a human reviews it.

## Consequences
Config changes take effect only after they merge.
