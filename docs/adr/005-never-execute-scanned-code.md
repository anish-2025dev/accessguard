# ADR 005: Never execute code from scanned repositories outside a disposable sandbox

- Status: Accepted
- Date: 2026-10-23

## Context
PRs, especially from forks, are untrusted. GitHub Security Lab warns that running PR code in a privileged context can compromise the repository. Importing a FastAPI app to read `app.routes` would run arbitrary module-level code.

## Decision
Code is treated as data: fetched via API/tarball/shallow clone and parsed, never imported, installed or built. The only exception is applying Supabase migrations and running Firebase emulator tests, which happens in a disposable container with no network, no secrets and resource limits. Ground-truth route extraction for the eval corpus runs offline in the same kind of sandbox, never on customer code.

## Consequences
Static resolution must handle dynamic patterns or report UNKNOWN.
