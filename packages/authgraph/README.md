# authgraph

The AccessGuard analysis engine and CLI. It builds an access fact graph (routes, the guards that
apply to them, and the data they touch) for a commit, and diffs base against head to report only
access-control regressions.

```
authgraph scan <path>                          # endpoints, guards, AUTH / NO_AUTH / UNKNOWN
authgraph diff <base-dir> <head-dir>           # findings introduced by head (JSON)
authgraph diff main..feature --format sarif    # two revisions of the repo in the cwd
authgraph diff main..HEAD --format text --fail-on high
```

Supported:
- FastAPI: decorators, `add_api_route`, `include_router` prefixes and dependencies, `mount`,
  `Depends` / `Security` / `Annotated` aliases, dependency classes and factories, cross-file
  imports including namespace packages and app factories.
- Express (Phase 3, tree-sitter): `app` / `Router` mount trees with source-order middleware,
  `route()` and `use()` chains, route tables, factories, `express-unless`, express-jwt / passport
  / openid-connect / oauth2-jwt-bearer / Clerk primitives, finale-rest resources, tsconfig paths.
- Data (Phase 3): Supabase migrations (pglast catalog replay), Firebase rules, client secrets.

| Rule | Fires when |
| --- | --- |
| AG-AUTH-001 | A new endpoint is NO_AUTH (inline for mutating/admin endpoints, advisory for reads) |
| AG-AUTH-002 | A guard was removed, its condition weakened (Z3), its failure path neutered, the check moved after a write, or an owner filter dropped |
| AG-AUTH-003 | A route on a mounted sub-app skips the parent app's auth dependencies |
| AG-ROLE-001 | A new or changed endpoint lacks a role check that >= 90% of its >= 4 router peers have, or a new admin-path write has none (heuristic) |
| AG-ROLE-002 | A request body with role/owner fields is mass-assigned on an endpoint without a role guard |
| AG-IDOR-001 | A request id reaches an ORM sink and no user context exists anywhere on the path (heuristic) |
| AG-IDOR-002 | A user is available but not tied to the object fetched by id (advisory, LLM-triaged) |
| AG-DATA-001 | A Supabase table is exposed: RLS off, `USING (true)` write policy, or an RLS-bypassing view |
| AG-DATA-002 | A Supabase policy passes on NULL (heuristic) |
| AG-DATA-003 | A Firebase rule is open to everyone, or lets any signed-in user write |
| AG-SECRET-001 | A service-role / secret key, or a secret env var with a client prefix, reaches client code |
| AG-CFG-001 | The PR widens `public_routes` / `auth_guards` in `.accessguard.yml` |

Configuration is read from the **base** tree only (ADR 006). Custom guards the scorer can't
classify can be confirmed in `.accessguard.yml` under `auth_guards`. Summaries are cached by git
blob SHA; set `AUTHGRAPH_CACHE_DIR` to persist them between runs.

`authgraph` never imports or executes code from the scanned repository; it parses source only
(ADR 005).
