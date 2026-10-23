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
from authgraph.facts.models import DataExposure, Loc
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


EXPOSED = [
    p / "head"
    for p in sorted(MUTATIONS.glob("m*_supabase_*"))
    if any(e.ops & {"select", "insert"} for e in analyze_supabase(DirectoryTree(p / "head"))[0])
]


@pytest.mark.parametrize("tree_dir", EXPOSED, ids=lambda p: p.parent.name)
def test_probes_prove_every_select_and_insert_exposure(
    sandbox: PostgresSandbox, tree_dir: Path
) -> None:
    """FR-3.8b positive: SET ROLE anon/authenticated reads a seeded row or inserts one."""
    result = sandbox.replay(DirectoryTree(tree_dir), probe=True)
    assert result.exposures
    for e in result.exposures:
        assert result.proven(e) == e.ops & {"select", "insert"}, (e, result.probes)


OWNED = """
create type status as enum ('draft', 'live');
create table public.notes (
  id bigint generated always as identity primary key,
  owner uuid not null references auth.users (id),
  status status not null,
  body text not null
);
alter table public.notes enable row level security;
create policy "own notes" on public.notes for all to authenticated
  using (auth.uid() = owner) with check (auth.uid() = owner);
"""


def test_probes_deny_owner_scoped_table(sandbox: PostgresSandbox, tmp_path: Path) -> None:
    """FR-3.8b negative: an exposure claimed on an owner-scoped table is denied at runtime."""
    mig = tmp_path / "supabase" / "migrations"
    mig.mkdir(parents=True)
    (mig / "0001_notes.sql").write_text(OWNED)
    claims = [
        DataExposure(
            resource="public.notes",
            role=role,
            ops={"select", "insert"},
            reason="rls_disabled",
            loc=Loc(path="x.sql", line=1),
        )
        for role in ("anon", "authenticated")
    ]
    result = sandbox.replay(DirectoryTree(tmp_path), probe=True, claims=claims)
    assert result.exposures == []
    outcomes = {(p.role, p.op): p.outcome for p in result.probes}
    assert outcomes == {
        ("anon", "select"): "denied",
        ("anon", "insert"): "denied",
        ("authenticated", "select"): "denied",
        ("authenticated", "insert"): "denied",
    }, result.probes
    assert all(result.proven(c) == set() for c in claims)
