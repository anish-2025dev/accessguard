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

Supported in Phase 1: FastAPI (decorators, `add_api_route`, `include_router` prefixes and
dependencies, `mount`, `Depends` / `Security` / `Annotated` aliases, dependency classes and
factories, cross-file imports including namespace packages and app factories).

| Rule | Fires when |
| --- | --- |
| AG-AUTH-001 | A new endpoint is NO_AUTH (inline for mutating/admin endpoints, advisory for reads) |
| AG-AUTH-002 | A guard was removed, its condition weakened (Z3), its failure path neutered, the check moved after a write, or an owner filter dropped |
| AG-AUTH-003 | A route on a mounted sub-app skips the parent app's auth dependencies |
| AG-ROLE-002 | A request body with role/owner fields is mass-assigned on an endpoint without a role guard |
| AG-CFG-001 | The PR widens `public_routes` / `auth_guards` in `.accessguard.yml` |

Configuration is read from the **base** tree only (ADR 006). Custom guards the scorer can't
classify can be confirmed in `.accessguard.yml` under `auth_guards`. Summaries are cached by git
blob SHA; set `AUTHGRAPH_CACHE_DIR` to persist them between runs.

`authgraph` never imports or executes code from the scanned repository; it parses source only
(ADR 005).
