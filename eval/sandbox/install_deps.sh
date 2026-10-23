#!/bin/sh
# Best-effort dependency install for a pinned corpus repo (build stage only; see Dockerfile).
# Installs requirements*.txt if present, else the [project] / Poetry dependencies declared in
# pyproject.toml (read with tomllib; the project itself is never built). Failures are tolerated so
# a partially-installable repo still yields its importable routers; dump_routes.py records errors.
set -u
dir="$1"
pip install -q fastapi uvicorn poetry-core || exit 1
found=0
for req in "$dir"/requirements.txt "$dir"/requirements/*.txt "$dir"/requirements-*.txt; do
  [ -f "$req" ] || continue
  found=1
  pip install -q -r "$req" || echo "WARN: $req failed" >&2
done
if [ "$found" -eq 0 ] && [ -f "$dir/pyproject.toml" ]; then
  python - "$dir/pyproject.toml" > /tmp/reqs.txt <<'EOF' || exit 1
import sys, tomllib
from pathlib import Path
from poetry.core.factory import Factory
from poetry.core.version.requirements import Requirement

project = Path(sys.argv[1])
with project.open("rb") as source:
    data = tomllib.load(source)
deps = list(data.get("project", {}).get("dependencies", []))
poetry = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
for name, constraints in poetry.items():
    if name.lower() == "python":
        continue
    for constraint in constraints if isinstance(constraints, list) else [constraints]:
        deps.append(Factory.create_dependency(name, constraint, root_dir=project.parent).to_pep_508())
for dep in deps:
    # Fail rather than drop constraints that cannot be represented as pip requirements.
    Requirement(dep)
    print(dep)
EOF
  # One at a time so a single unresolvable pin does not block the rest.
  while read -r dep; do
    [ -n "$dep" ] && { pip install -q "$dep" || echo "WARN: $dep failed" >&2; }
  done < /tmp/reqs.txt
fi
exit 0
