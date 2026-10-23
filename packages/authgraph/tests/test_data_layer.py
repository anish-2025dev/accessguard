"""Data layer (FR-3.8, FR-3.9, FR-3.10): Supabase catalog replay, Firebase rules, secrets."""

from __future__ import annotations

import base64
import json
from pathlib import Path

from authgraph.data.firebase import analyze_rtdb, analyze_rules_file
from authgraph.data.secrets import is_client_file, scan_text
from authgraph.data.supabase import analyze_supabase
from authgraph.workspace.tree import DirectoryTree

from .helpers import write_tree

SQL = """
create table public.profiles (id uuid primary key, name text);
alter table public.profiles enable row level security;
create policy "own" on public.profiles for update using (auth.uid() = id or id is null);
create table public.audit (id bigint);
create table public.posts (id bigint);
alter table public.posts enable row level security;
create policy "anyone" on public.posts for insert to anon with check (true);
create table public.secrets (v text);
alter table public.secrets enable row level security;
create view public.leak as select * from public.secrets;
create view public.ok with (security_invoker = true) as select * from public.secrets;
create table public.internal (id bigint);
revoke all on public.internal from anon, authenticated;
create table private.hidden (id bigint);
"""


def _supabase(tmp: Path, sql: str, config: str = "") -> set[tuple[str, str, str]]:
    files = {"supabase/migrations/0001_init.sql": sql}
    if config:
        files["supabase/config.toml"] = config
    ex, errors = analyze_supabase(DirectoryTree(write_tree(tmp, files)))
    assert errors == []
    return {(e.resource, e.role, e.reason) for e in ex}


def test_supabase_catalog_checks(tmp_path: Path) -> None:
    got = _supabase(tmp_path, SQL)
    assert got == {
        ("public.profiles", "public", "null_fail_open"),
        ("public.audit", "anon", "rls_disabled"),
        ("public.audit", "authenticated", "rls_disabled"),
        ("public.posts", "anon", "policy_true_write"),
        ("public.leak", "anon", "security_definer_view"),
    }


def test_supabase_exposed_schemas_come_from_config(tmp_path: Path) -> None:
    got = _supabase(tmp_path, SQL, '[api]\nschemas = ["public", "private"]\n')
    assert ("private.hidden", "anon", "rls_disabled") in got


def test_supabase_later_migrations_and_drops(tmp_path: Path) -> None:
    sql = (
        "create table t (id int);\n"  # unqualified -> public
        "alter table t enable row level security;\n"
        'create policy "p" on t for delete using (true);\n'
        'drop policy "p" on t;\n'
        "alter table t rename to t2;\n"
    )
    assert _supabase(tmp_path, sql) == set()


def test_firestore_rules() -> None:
    src = """rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    function signedIn() { return request.auth != null; }
    match /a/{id} { allow read; }
    match /b/{id} { allow write: if signedIn(); }
    match /c/{id} { allow read, write: if request.auth.uid == id; }
    match /d/{id} { allow read: if request.time < timestamp.date(2030, 1, 1); }
  }
}"""
    got = {(e.resource.rsplit("/", 2)[-2], e.reason) for e in analyze_rules_file("f.rules", src)}
    assert got == {("a", "firebase_open"), ("b", "firebase_auth_only"), ("d", "firebase_open")}


def test_realtime_database_rules() -> None:
    doc = {"rules": {"chat": {".read": True, "$uid": {".write": "auth.uid === $uid"}}}}
    got = analyze_rtdb("database.rules.json", json.dumps(doc, indent=1))
    assert [(e.resource, e.reason, e.loc.line) for e in got] == [("database.rules.json:/chat", "firebase_open", 4)]


def _jwt(role: str) -> str:
    def b(d: dict[str, str]) -> str:
        return base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")

    return f"{b({'alg': 'HS256'})}.{b({'iss': 'test', 'role': role})}.c2lnbmF0dXJlLXRlc3Q"


def test_secrets_client_classification_and_redaction() -> None:
    assert is_client_file("src/components/Nav.tsx", "")
    assert not is_client_file("src/app/api/x/route.ts", "")
    assert not is_client_file("src/lib/db.ts", "'use server'\n")
    found = scan_text("src/lib/client.ts", f"const k = '{_jwt('service_role')}'\n")
    assert [s.kind for s in found] == ["supabase_service_role_jwt"]
    assert _jwt("service_role") not in found[0].detail  # only a hash is kept
    assert scan_text("src/lib/client.ts", f"const k = '{_jwt('anon')}'\n") == []
    assert scan_text("server/admin.ts", f"const k = '{_jwt('service_role')}'\n") == []
