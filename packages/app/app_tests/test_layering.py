"""Dependency rule (PLAN.md §6.1): app imports authgraph; authgraph imports nothing from app."""

import ast
from pathlib import Path

AUTHGRAPH_SRC = Path(__file__).parents[2] / "authgraph" / "src" / "authgraph"
FORBIDDEN = ("accessguard_app", "accessguard_verifier")


def test_authgraph_does_not_import_app_or_verifier() -> None:
    offenders = []
    for path in AUTHGRAPH_SRC.rglob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            names: list[str] = []
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module]
            offenders += [f"{path}: {n}" for n in names if n.split(".")[0] in FORBIDDEN]
    assert offenders == []
