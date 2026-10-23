"""AG-ROLE-001 peer consistency (FR-3.4, PLAN.md §6.4)."""

from __future__ import annotations

from pathlib import Path

import pytest
from authgraph.api import diff_trees
from authgraph.rules.consistency import z_score
from authgraph.workspace.tree import DirectoryTree

from .helpers import DEPS, write_tree


@pytest.mark.parametrize(
    ("e", "n", "flag"),
    [(9, 10, True), (4, 4, True), (3, 4, False), (19, 20, True), (8, 10, False)],
)
def test_z_threshold_is_ninety_percent_of_peers(e: int, n: int, flag: bool) -> None:
    assert (z_score(e, n) >= 0) is flag


def _router(n_admin: int, extra: str = "") -> str:
    routes = "".join(
        f'@router.post("/a{i}")\ndef a{i}(u=Depends(require_admin)):\n    return 1\n\n'
        for i in range(n_admin)
    )
    return (
        "from fastapi import APIRouter, Depends\n"
        "from deps import get_current_user, require_admin\n"
        f"router = APIRouter()\n\n{routes}{extra}"
    )


MAIN = """
from fastapi import FastAPI
import staff
app = FastAPI()
app.include_router(staff.router, prefix="/staff")
"""
NEW = '@router.post("/new")\ndef new(u=Depends(get_current_user)):\n    return 1\n'


def _rules(tmp: Path, n_admin: int, new: str) -> list[str]:
    files = {"deps.py": DEPS, "main.py": MAIN}
    b = write_tree(tmp / "base", {**files, "staff.py": _router(n_admin)})
    h = write_tree(tmp / "head", {**files, "staff.py": _router(n_admin, new)})
    return [f.rule_id for f in diff_trees(DirectoryTree(b), DirectoryTree(h)).findings]


def test_new_write_without_peer_role_is_reported(tmp_path: Path) -> None:
    assert _rules(tmp_path, 4, NEW) == ["AG-ROLE-001"]


def test_too_few_peers_and_unauthenticated_routes_are_not_reported(tmp_path: Path) -> None:
    assert _rules(tmp_path / "a", 3, NEW) == []
    unauth = '@router.post("/new")\ndef new():\n    return 1\n'
    assert "AG-ROLE-001" not in _rules(tmp_path / "b", 4, unauth)  # AG-AUTH-001's finding
