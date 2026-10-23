# ADR 017: Pilot-driven precision fixes for the data layer

- Status: Accepted
- Date: 2026-10-23

## Context
The Phase 4 pilot (`docs/pilot.md`) replayed the recent history of public AI-built repositories:
Lovable/gpt-engineer, Claude Code and Copilot projects, mostly React + Supabase. Almost all
first-run findings were data-layer findings, and the false positives fell into three classes.
There was also one class of true but rarely actionable inline findings.

## Decision
1. **NULL fail-open is structural, not textual.** AG-DATA-002 used to fire whenever a policy
   contained `OR`, `IS NULL` and an `auth.*()` call. It now parses the expression (pglast) and
   expands it into OR branches. A branch fails open only when both of these hold:
   - it tests the principal, or a column compared with it, for NULL;
   - no AND-ed comparison with `auth.*()` makes it NULL for an anonymous caller.

   Fixtures: m47 positive, m57 negative.
2. **No phantom tables.** The two FP classes and their fixes:
   - `GRANT ... ON <view>` invented a table without RLS. Grants now apply only to tables the
     replay created. Fixture: m58.
   - `CREATE POLICY` on a table created before the migrations start (in the dashboard) invented
     one too. Such a table now has **unknown** RLS: three-valued, and never reported as
     disabled. Fixture: m59.
3. **Write-only inserts are heuristic.** Take an `INSERT ... WITH CHECK (true)` policy for a role
   that has no `USING (true)` read policy on the table. That is a drop box: a contact form, a
   feedback form, an order or reservation request. It can be spammed, but it leaks nothing. It
   gets its own reason, `write_only_insert`, in AG-DATA-001 at **heuristic** tier: listed in the
   check run, not posted inline.

   Insert-anything on a table the same role can read stays deterministic, because it is
   defacement of shared content. Example: "Service role can insert videos" without a `TO`
   clause. Fixtures: m60 heuristic, m61 deterministic.

   The eval harness now checks an optional expected `tier` per finding.
4. **Probes act as `anon` for `PUBLIC`.** `SET ROLE public` is invalid (22023). Since `PUBLIC`
   includes `anon`, an exposure granted to `PUBLIC` is probed as `anon` (ADR 016).

## Consequences
- The static engine and the sandbox use the same `readable_by`/`write_reason` helpers. The
  differential test (static vs real catalog) covers the new reason.
- A repository whose public form should not take anonymous writes still gets the finding, in
  the check run.
- ENGINE_VERSION 28 invalidates cached summaries.
