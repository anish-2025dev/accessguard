#!/usr/bin/env bash
# Stop hook: Claude can't finish a turn while lint, types or tests fail.
# Exit 2 blocks the stop and sends stderr back to Claude to fix.
INPUT=$(cat)

# Avoid an endless loop: if this hook already forced a continuation, let Claude stop.
if [ "$(echo "$INPUT" | jq -r '.stop_hook_active')" = "true" ]; then
  exit 0
fi

cd "$CLAUDE_PROJECT_DIR" || exit 0

# Nothing to check until the Python workspace exists (Phase 0 scaffolding).
[ -f pyproject.toml ] || exit 0
command -v uv >/dev/null 2>&1 || { echo "uv not installed; skipping checks" >&2; exit 0; }

FAILED=0
OUT=""

run() {
  local name="$1"; shift
  local res
  if ! res=$("$@" 2>&1); then
    FAILED=1
    OUT+=$'\n'"=== $name failed ==="$'\n'"$(echo "$res" | tail -40)"
  fi
}

run "ruff" uv run --quiet ruff check .
[ -d packages/authgraph ] && run "mypy" uv run --quiet mypy packages/authgraph
if ls tests packages/*/tests >/dev/null 2>&1; then
  run "pytest" uv run --quiet pytest -q -x
fi

if [ "$FAILED" -eq 1 ]; then
  echo "Checks failed. Fix the root cause (don't skip or weaken tests), then finish.$OUT" >&2
  exit 2
fi
exit 0
