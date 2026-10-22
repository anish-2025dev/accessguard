#!/usr/bin/env bash
# PostToolUse: format edited Python files. Never blocks; silently skips if tooling isn't set up yet.
INPUT=$(cat)
FILE=$(echo "$INPUT" | jq -r '.tool_input.file_path // empty')

[[ "$FILE" == *.py ]] || exit 0
command -v uv >/dev/null 2>&1 || exit 0
[ -f "$CLAUDE_PROJECT_DIR/pyproject.toml" ] || exit 0

cd "$CLAUDE_PROJECT_DIR" || exit 0
uv run --quiet ruff format "$FILE" >/dev/null 2>&1
uv run --quiet ruff check --fix "$FILE" >/dev/null 2>&1
exit 0
