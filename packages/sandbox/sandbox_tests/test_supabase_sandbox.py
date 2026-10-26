"""Differential test: static catalog replay (authgraph) == real Postgres catalog (sandbox), on
every Supabase eval fixture. Needs Docker; skipped otherwise."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest
from accessguard_sandbox.supabase import PostgresSandbox
from authgraph.data.supabase import analyze_supabase
from authgraph.workspace.tree import DirectoryTree

MUTATIONS = Path(__file__).resolve().parents[3] / "eval" / "mutations"
CASES = sorted(p for p in MUTATIONS.glob("m*_supabase_*") for p in (p / "base", p / "head"))


def _docker() -> bool:
    if shutil.which("docker") is None:
        return False
    return subprocess.run(["docker", "info"], capture_output=True).returncode == 0


pytestmark = pytest.mark.skipif(not _docker(), reason="docker is not available")


@pytest.fixture(scope="module")
def sandbox() -> PostgresSandbox:
    return PostgresSandbox(os.environ.get("AG_TEST_PG_IMAGE"))


@pytest.mark.parametrize("tree_dir", CASES, ids=lambda p: f"{p.parent.name}/{p.name}")
def test_static_replay_matches_postgres_catalog(sandbox: PostgresSandbox, tree_dir: Path) -> None:
    tree = DirectoryTree(tree_dir)
    static, errors = analyze_supabase(tree)
    real = sandbox.replay(tree)
    assert errors == [] and real.errors == []

    def keys(xs: list) -> set[tuple[str, str, str, frozenset[str]]]:
        return {(e.resource, e.role, e.reason, frozenset(e.ops)) for e in xs}

    assert keys(static) == keys(real.exposures)
