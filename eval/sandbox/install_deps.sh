#!/bin/sh
# Best-effort dependency install for a pinned corpus repo (build stage only; see Dockerfile).
# Installs requirements*.txt if present, else the [project] / Poetry dependencies declared in
# pyproject.toml (read with tomllib; the project itself is never built). Failures are tolerated so
# a partially-installable repo still yields its importable routers; dump_routes.py records errors.
set -u
dir="$1"
exec 2>>/tmp/install.log  # surfaced in the dump output for diagnosis
pip install -q fastapi uvicorn || exit 1
found=0
for req in "$dir"/requirements.txt "$dir"/requirements/*.txt "$dir"/requirements-*.txt; do
  [ -f "$req" ] || continue
  found=1
  if ! pip install -q -r "$req"; then
    echo "WARN: $req failed as a set; installing line by line" >&2
    grep -vE '^\s*(#|-|$)' "$req" | while read -r dep; do
      pip install -q "$dep" || echo "WARN: $dep failed" >&2
    done
  fi
done
if [ "$found" -eq 0 ] && [ -f "$dir/pyproject.toml" ]; then
  python - "$dir/pyproject.toml" > /tmp/reqs.txt <<'EOF'
import sys, tomllib
data = tomllib.load(open(sys.argv[1], "rb"))
deps = list(data.get("project", {}).get("dependencies", []))
poetry = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
deps += [name for name in poetry if name.lower() != "python"]
print("\n".join(deps))
EOF
  # One at a time so a single unresolvable pin does not block the rest.
  while read -r dep; do
    [ -n "$dep" ] && { pip install -q "$dep" || echo "WARN: $dep failed" >&2; }
  done < /tmp/reqs.txt
fi
# Some apps read their own installed metadata (importlib.metadata.version("pkg")).
if [ "${INSTALL_SELF:-0}" = "1" ]; then
  pip install -q --no-deps "$dir" || echo "WARN: self install failed" >&2
fi
cp /tmp/install.log /install.log 2>/dev/null || true
exit 0
