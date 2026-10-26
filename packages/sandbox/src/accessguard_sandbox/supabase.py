"""Replay Supabase migrations in a disposable, network-less Postgres and read the catalog
(FR-3.8; ADR 005: migrations run only in this sandbox).

The container runs with ``--network none``, no capabilities, a tmpfs data directory, memory and
PID limits, and is removed afterwards. SQL is sent through ``docker exec psql`` on stdin, so the
database never needs a network. On a plain Postgres image the Supabase roles and ``auth``
helpers are created first with Supabase's default privileges (anon and authenticated receive
all privileges on new tables in ``public``); a ``supabase/postgres`` image already has them.

Catalog facts (Postgres 15+ system catalogs; https://www.postgresql.org/docs/current/catalogs.html):
``pg_class.relrowsecurity`` / ``reloptions`` (``security_invoker``), ``has_table_privilege``,
``pg_policies``, and view-to-table dependencies through ``pg_rewrite`` / ``pg_depend``.
The resulting ``DataExposure`` facts use the same reasons as ``authgraph.data.supabase``.
"""

from __future__ import annotations

import json
import os
import subprocess
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from authgraph.data.supabase import (
    ALL_PRIVS,
    API_ROLES,
    exposed_schemas,
    fails_open,
    is_true,
    migration_files,
)
from authgraph.facts.models import DataExposure, Loc
from authgraph.workspace.tree import SourceTree

DEFAULT_IMAGE = "public.ecr.aws/docker/library/postgres:16"
BOOTSTRAP = """
do $$ begin
  if not exists (select 1 from pg_roles where rolname = 'anon') then
    create role anon nologin; create role authenticated nologin; create role service_role nologin;
  end if;
end $$;
create schema if not exists auth;
create table if not exists auth.users (id uuid primary key);
create or replace function auth.uid() returns uuid language sql stable as
  $f$ select nullif(current_setting('request.jwt.claim.sub', true), '')::uuid $f$;
create or replace function auth.role() returns text language sql stable as
  $f$ select nullif(current_setting('request.jwt.claim.role', true), '') $f$;
create or replace function auth.jwt() returns jsonb language sql stable as
  $f$ select coalesce(nullif(current_setting('request.jwt.claims', true), ''), '{}')::jsonb $f$;
grant usage on schema public, auth to anon, authenticated, service_role;
alter default privileges in schema public grant all on tables to anon, authenticated, service_role;
"""
CATALOG = """
select json_build_object(
 'relations', coalesce((select json_agg(r) from (
   select n.nspname as schema, c.relname as name, c.relkind as kind,
          c.relrowsecurity as rls, coalesce(c.reloptions, '{}') as options,
          (select json_object_agg(role, privs) from (
             select role, array(select p from unnest(array['select','insert','update','delete']) p
                                where has_table_privilege(role, c.oid, p)) as privs
             from unnest(array['anon','authenticated']) role) x) as privileges
   from pg_class c join pg_namespace n on n.oid = c.relnamespace
   where c.relkind in ('r', 'p', 'v') and n.nspname = any(:'schemas'::text[])) r), '[]'),
 'policies', coalesce((select json_agg(p) from (
   select schemaname as schema, tablename as name, policyname, permissive, roles, cmd, qual,
          with_check
   from pg_policies where schemaname = any(:'schemas'::text[])) p), '[]'),
 'view_sources', coalesce((select json_agg(d) from (
   select distinct vn.nspname as vschema, v.relname as vname, tn.nspname as tschema,
          t.relname as tname
   from pg_class v join pg_namespace vn on vn.oid = v.relnamespace
   join pg_rewrite rw on rw.ev_class = v.oid
   join pg_depend dep on dep.objid = rw.oid
   join pg_class t on t.oid = dep.refobjid join pg_namespace tn on tn.oid = t.relnamespace
   where v.relkind = 'v' and t.relkind in ('r', 'p') and t.oid <> v.oid) d), '[]'))
"""
RUN_FLAGS = [
    "--rm",
    "-d",
    "--network",
    "none",
    "--cap-drop",
    "ALL",
    "--cap-add",
    "CHOWN",
    "--cap-add",
    "SETUID",
    "--cap-add",
    "SETGID",
    "--cap-add",
    "DAC_OVERRIDE",
    "--cap-add",
    "FOWNER",
    "--security-opt",
    "no-new-privileges",
    "--memory",
    "1g",
    "--pids-limit",
    "256",
    "--tmpfs",
    "/var/lib/postgresql/data:size=512m",
]


@dataclass
class SandboxResult:
    exposures: list[DataExposure]
    errors: list[str] = field(default_factory=list)
    files: int = 0


class SandboxError(RuntimeError):
    pass


def _run(cmd: list[str], stdin: str | None = None, timeout: float = 120) -> str:
    out = subprocess.run(cmd, input=stdin, capture_output=True, text=True, timeout=timeout)
    if out.returncode != 0:
        raise SandboxError(out.stderr.strip()[-2000:] or f"exit {out.returncode}")
    return out.stdout


class PostgresSandbox:
    """One disposable database per call to ``replay``."""

    def __init__(self, image: str | None = None, start_timeout: float = 60) -> None:
        self.image = image or os.environ.get("AG_SANDBOX_PG_IMAGE", DEFAULT_IMAGE)
        self.start_timeout = start_timeout

    def _psql(self, name: str, sql: str, *args: str) -> str:
        cmd = ["docker", "exec", "-i", name, "psql", "-U", "postgres", "-X", "-q", "-At"]
        return _run([*cmd, "-v", "ON_ERROR_STOP=1", *args], stdin=sql)

    def _start(self) -> str:
        name = f"ag-sandbox-{uuid.uuid4().hex[:12]}"
        env = ["-e", "POSTGRES_PASSWORD=sandbox", "-e", "POSTGRES_HOST_AUTH_METHOD=trust"]
        _run(["docker", "run", *RUN_FLAGS, "--name", name, *env, self.image], timeout=300)
        deadline = time.time() + self.start_timeout
        while time.time() < deadline:
            ready = subprocess.run(
                [
                    "docker",
                    "exec",
                    name,
                    "pg_isready",
                    "-U",
                    "postgres",
                    "-h",
                    "/var/run/postgresql",
                ],
                capture_output=True,
            )
            if ready.returncode == 0:
                try:  # the entrypoint restarts the server once after initdb
                    self._psql(name, "select 1;")
                    return name
                except SandboxError:
                    pass
            time.sleep(0.5)
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)
        raise SandboxError("postgres did not become ready")

    def replay(self, tree: SourceTree) -> SandboxResult:
        files = migration_files(tree)
        result = SandboxResult([], files=len(files))
        if not files:
            return result
        name = self._start()
        try:
            self._psql(name, BOOTSTRAP)
            for path in files:
                try:
                    self._psql(name, tree.read(path).decode("utf-8", "replace"))
                except SandboxError as e:
                    result.errors.append(f"{path}: {str(e).splitlines()[-1][:200]}")
            schemas = exposed_schemas(tree)
            arr = "{" + ",".join(schemas) + "}"
            raw = self._psql(name, CATALOG + ";", "-v", f"schemas={arr}")
            result.exposures = catalog_exposures(json.loads(raw), schemas, files[-1])
        finally:
            subprocess.run(["docker", "rm", "-f", name], capture_output=True)
        return result


def _opts(options: list[str]) -> dict[str, str]:
    return dict(o.split("=", 1) for o in options if "=" in o)


def catalog_exposures(
    cat: dict[str, Any], schemas: tuple[str, ...], path: str
) -> list[DataExposure]:
    loc = Loc(path=path, line=1)
    rels = {(r["schema"], r["name"]): r for r in cat["relations"]}
    out: list[DataExposure] = []
    for r in rels.values():
        if r["kind"] == "v" or r["rls"]:
            continue
        for role in API_ROLES:
            privs = set((r["privileges"] or {}).get(role) or []) & ALL_PRIVS
            if privs:
                out.append(
                    DataExposure(
                        resource=f"{r['schema']}.{r['name']}",
                        role=role,
                        ops=privs,
                        reason="rls_disabled",
                        loc=loc,
                    )
                )
    for p in cat["policies"]:
        if not rels.get((p["schema"], p["name"]), {}).get("rls"):
            continue
        roles = [x for x in p["roles"] if x in {"anon", "authenticated", "public"}]
        if p["permissive"] != "PERMISSIVE" or not roles:
            continue
        cmd = p["cmd"].lower()
        ops = {"insert", "update", "delete"} if cmd == "all" else {cmd}
        using, check = p["qual"], p["with_check"]
        opens = is_true(check) or (cmd in {"update", "delete", "all"} and is_true(using))
        resource = f"{p['schema']}.{p['name']}"
        if cmd in {"insert", "update", "delete", "all"} and opens:
            out += [
                DataExposure(
                    resource=resource,
                    role=x,
                    ops=ops & ALL_PRIVS,
                    reason="policy_true_write",
                    loc=loc,
                )
                for x in roles
            ]
        if fails_open(using) or fails_open(check):
            o = {"select"} if cmd == "select" else ops & ALL_PRIVS
            out += [
                DataExposure(resource=resource, role=x, ops=o, reason="null_fail_open", loc=loc)
                for x in roles
            ]
    sources: dict[tuple[str, str], list[tuple[str, str]]] = {}
    for d in cat["view_sources"]:
        sources.setdefault((d["vschema"], d["vname"]), []).append((d["tschema"], d["tname"]))
    for key, r in rels.items():
        if r["kind"] != "v" or _opts(r["options"]).get("security_invoker") in {"true", "on", "1"}:
            continue
        if any(rels.get(t, {}).get("rls") for t in sources.get(key, [])):
            out.append(
                DataExposure(
                    resource=f"{key[0]}.{key[1]}",
                    role="anon",
                    ops={"select"},
                    reason="security_definer_view",
                    loc=loc,
                )
            )
    return out
