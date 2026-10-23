# authgraph

The AccessGuard analysis engine and CLI. It builds an access fact graph (routes, the guards that
apply to them, and the data they touch) for a commit, and diffs base against head to report only
access-control regressions.

```
authgraph diff <base-path> <head-path>
```

`authgraph` never imports or executes code from the scanned repository; it parses source only.
