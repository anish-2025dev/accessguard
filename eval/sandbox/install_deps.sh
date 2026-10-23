#!/bin/sh
# Best-effort dependency install for a pinned corpus repo (build stage only; see Dockerfile).
# Order of preference: the repo's uv.lock (exact pins), requirements*.txt, then the [project] /
# Poetry dependencies declared in pyproject.toml (read with tomllib; the project is never built).
# Failures are tolerated so a partially-installable repo still yields its importable routers;
# the log is copied to /install.log and dump_routes.py reports it when no routes come out.
set -u
dir="$1"
exec 2>>/tmp/install.log

install_list() {  # pip install -r FILE, falling back to one requirement at a time
  if ! pip install -q -r "$1"; then
    echo "WARN: $1 failed as a set; installing line by line" >&2
    grep -vE '^\s*(#|-|$)' "$1" | while read -r dep; do
      pip install -q "$dep" || echo "WARN: $dep failed" >&2
    done
  fi
}

pip install -q fastapi uvicorn || exit 1
found=0

for lock in "$dir/uv.lock" /src/uv.lock; do
  [ -f "$lock" ] || continue
  if pip install -q uv && (cd "$(dirname "$lock")" && uv export --frozen --no-hashes \
      --all-packages --no-emit-project --no-emit-workspace -o /tmp/uv-reqs.txt); then
    install_list /tmp/uv-reqs.txt
    found=1
  else
    echo "WARN: uv export failed for $lock" >&2
  fi
  break
done

if [ "$found" -eq 0 ] && [ -f "$dir/poetry.lock" ]; then
  # Exact pins from poetry.lock (main category / main group only).
  python - "$dir/poetry.lock" > /tmp/poetry-reqs.txt <<'PY'
import sys, tomllib
lock = tomllib.load(open(sys.argv[1], "rb"))
for pkg in lock.get("package", []):
    groups = pkg.get("groups") or [pkg.get("category", "main")]
    if "main" in groups:
        print(f"{pkg['name']}=={pkg['version']}")
PY
  install_list /tmp/poetry-reqs.txt
  found=1
fi

if [ "$found" -eq 0 ]; then
  for req in "$dir"/requirements.txt "$dir"/requirements/*.txt "$dir"/requirements-*.txt; do
    [ -f "$req" ] || continue
    found=1
    install_list "$req"
  done
fi

if [ "$found" -eq 0 ] && [ -f "$dir/pyproject.toml" ]; then
  python - "$dir/pyproject.toml" > /tmp/reqs.txt <<'EOF'
import sys, tomllib
data = tomllib.load(open(sys.argv[1], "rb"))
deps = list(data.get("project", {}).get("dependencies", []))
poetry = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
deps += [name for name in poetry if name.lower() != "python"]
print("\n".join(deps))
EOF
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
