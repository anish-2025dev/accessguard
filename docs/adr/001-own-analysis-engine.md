# ADR 001: Build our own analysis engine on `ast` + tree-sitter

- Status: Accepted
- Date: 2026-10-23

## Context
AccessGuard must resolve auth that is inherited across files (FastAPI router/app dependencies, Express middleware order) on private repos, at PR time.

- CodeQL CLI licence forbids use on non-open-source codebases without a paid GitHub Advanced Security licence.
- Semgrep CE only tracks data within a single function/file; Semgrep's maintained rules may not be offered as a service; Semgrep Pro cross-file analysis does not run on diff-aware scans.
- GitHub archived stack-graphs (Sept 2025).

## Decision
Own the analysis layer: Python `ast` for Python, tree-sitter for JS/TS, per-file summaries cached by git blob SHA, our own import resolution and framework router graphs. Use pyright / TypeScript compiler API only for references syntax can't resolve. CodeQL only as an optional offline/nightly tool for building the eval corpus.

## Consequences
More engineering up front; full control over accuracy, speed (~30 s PR scans target) and licensing.
