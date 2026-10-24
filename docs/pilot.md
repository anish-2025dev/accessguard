# Pilot: AccessGuard on public AI-built repositories

Phase 4 exit evidence (PLAN.md §Real-world proof, §4). AccessGuard was replayed over the recent
history of **34 public repositories built with AI coding tools** — Lovable / gpt-engineer
(31 repos, identified by the `gpt-engineer-app[bot]` author and the Lovable README), plus
Claude Code, Cursor and Copilot projects (3). The corpus skews toward React + Supabase, which is
what these tools generate. Repository list and pinned commits: `eval/corpus/checkouts/pilot-*`
(blobless clones; see `scratchpad/pilot/final.txt` for the source list).

## Method
Each repository's last 100 first-parent commits that touch source, SQL, rules or env files were
diffed against their parent, exactly as a push to `main` would be scanned
(`eval/tools/replay_history.py pilot-<name> --commits 100`). Every finding was hand-labelled in
`eval/corpus/labels/pilot-<name>.yaml`:

- **label** (`tp`/`fp`): is the reported access change factually real?
- **actionable**: would a reviewer act on it, or is the access intended (PLAN.md §1, the
  "effective false positive" metric)?

Reproduce: `python eval/tools/precision_table.py --pilot --markdown`.

## Results

**34 repositories, 1071 commits replayed, 32 findings in 13 repositories.** No finding was a
factual false positive.

| Rule | Findings | TP | FP | Precision | Inline (deterministic) | Inline FP |
|---|---|---|---|---|---|---|
| AG-DATA-001 | 24 | 24 | 0 | 100% | 16 | 0 |
| AG-DATA-002 | 4 | 4 | 0 | 100% | 0 | 0 |
| AG-DATA-003 | 2 | 2 | 0 | 100% | 1 | 0 |
| AG-SECRET-001 | 2 | 2 | 0 | 100% | 2 | 0 |

Effective precision (would a reviewer act), by tier:

| Tier | Findings | Actionable | Effective precision |
|---|---|---|---|
| deterministic (posted inline) | 19 | 18 | **95%** |
| heuristic (check run only) | 13 | 3 | 23% |

The deterministic tier — the findings AccessGuard posts as inline PR comments — is at 95%
effective precision, within the Phase 1 goal of ≤10% effective false positives. The single
non-actionable deterministic finding is an aggregate `*_counts` view intended to be public.
Heuristic findings (public insert-only forms, guest-create flows) are mostly intended; by design
they appear only in the check-run summary and never gate a PR or post an inline comment.

## What it found (a sample)
- **Secrets in client bundles**: a Stripe secret key and a secret env var carrying a
  client-bundle prefix (`hyuga611/vibe-checkup`).
- **RLS disabled on exposed tables**: `notification_preferences` (Promo_Gifts),
  `subscription_plans` (nourbook), a `_synchro_test` table left in a migration (tiro-finance) —
  all world read/write through the Supabase Data API.
- **`SECURITY DEFINER` views bypassing RLS**: `players_public` exposing player PII including
  phone numbers (tee-time-toolkit); a system-health dashboard and an insights cache (Promo_Gifts).
- **`using (true)` write policies**: an `event_activity_log` any authenticated user can rewrite
  (the-event-planner); public update on `sub_users` / `public_board_access` (daily-booking).
- **NULL fail-open policies**: `(auth.uid() IS NULL AND ...)` branches letting an anonymous
  caller delete or update `customers` and `tasks` (daily-booking).

## False-positive sources found and fixed
The first pilot run surfaced four FP sources in the data-layer rules, all now fixed with eval
fixtures and an ADR (ADR 017):

1. **Textual NULL fail-open** fired on any policy containing `OR`, `IS NULL` and `auth.*()`. Now
   the policy is parsed (pglast) and a branch fails open only when it tests the principal for NULL
   *without* an AND-ed comparison that is itself NULL for an anonymous caller (m47 / m57).
2. **`GRANT ... ON <view>`** invented a phantom table reported as RLS-disabled (m58).
3. **`CREATE POLICY` on a dashboard-created table** (one no migration defines) invented a table
   with unknown RLS; unknown is now three-valued and never reported (m59).
4. **Insert-only "drop box" policies** (contact, feedback, order and reservation forms: public
   insert on rows the role cannot read back) were deterministic. They are now the
   `write_only_insert` reason at heuristic tier — a spam/abuse note in the check run, not an
   inline leak finding (m60 deterministic vs m61 heuristic).

After these fixes, `make eval` is 61/61 and the pilot has zero factual false positives.

## v1.0
The exit gate asks for a tagged v1.0 with a published precision table. The precision table is
published here and in the README. **v1.0 is intentionally not tagged in this session**: tagging a
release is a maintainer decision, and the pilot corpus is third-party code we do not own. A
maintainer should tag `v1.0` once they have reviewed this table.
