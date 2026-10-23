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

Proof probes (FR-3.8b, ADR 016): after the catalog is read, every exposure is probed in the same
database, one rolled-back transaction per (relation, role, op). The superuser seeds a row with
``session_replication_role = replica`` (foreign-key triggers off), then ``SET LOCAL ROLE`` to the
API role, with ``request.jwt.claims`` set to a fresh ``sub`` for ``authenticated``, and attempts:

* ``select``: proven when the seeded row is visible;
* ``insert``: proven when the insert succeeds or fails only on a data constraint (SQLSTATE class
  23). Postgres checks privileges and RLS ``WITH CHECK`` before NOT NULL/CHECK constraints, so a
  23xxx error means access was granted; 42501 means denied.

Errors use psql ``VERBOSITY sqlstate`` (https://www.postgresql.org/docs/16/app-psql.html).
"""

from __future__ import annotations

import json
import os
import subprocess
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Literal

from authgraph.data.supabase import (
    ALL_PRIVS,
    API_ROLES,
    exposed_schemas,
    fails_open,
    is_true,
    migration_files,
    readable_by,
    write_reason,
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


COLUMNS = """
select json_agg(c) from (
  select n.nspname as schema, t.relname as name, a.attname as col, ty.typname as type,
         ty.typtype as typtype, ty.typcategory as category,
         (select e.enumlabel from pg_enum e where e.enumtypid = ty.oid
          order by e.enumsortorder limit 1) as first_label
  from pg_attribute a join pg_class t on t.oid = a.attrelid
  join pg_namespace n on n.oid = t.relnamespace join pg_type ty on ty.oid = a.atttypid
  where t.relkind in ('r', 'p') and n.nspname = any(:'schemas'::text[]) and a.attnum > 0
    and not a.attisdropped and a.attnotnull and not a.atthasdef and a.attidentity = ''
    and a.attgenerated = '') c
"""
PROBE_OPS = ("select", "insert")
Outcome = Literal["proven", "denied", "inconclusive"]


@dataclass(frozen=True)
class Probe:
    resource: str
    role: str
    op: str
    outcome: Outcome
    detail: str = ""


@dataclass
class SandboxResult:
    exposures: list[DataExposure]
    errors: list[str] = field(default_factory=list)
    files: int = 0
    probes: list[Probe] = field(default_factory=list)

    def proven(self, e: DataExposure) -> set[str]:
        """The ops of ``e`` that a probe demonstrated."""
        return {
            p.op
            for p in self.probes
            if (p.resource, p.role) == (e.resource, e.role)
            and p.op in e.ops
            and p.outcome == "proven"
        }


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

    def _try(self, name: str, sql: str) -> tuple[str | None, str]:
        """Run ``sql``; (None, stdout) on success, else (SQLSTATE, "")."""
        try:
            return None, self._psql(name, "\\set VERBOSITY sqlstate\n" + sql)
        except SandboxError as e:
            last = str(e).splitlines()[-1] if str(e) else ""
            return (last.split()[-1] if last.startswith("ERROR:") else "?"), ""

    def replay(
        self,
        tree: SourceTree,
        probe: bool = False,
        claims: list[DataExposure] | None = None,
    ) -> SandboxResult:
        """Replay migrations and read the catalog. ``probe`` also probes the catalog exposures
        plus any ``claims`` (for example the static engine's exposures) against the database."""
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
            cat = json.loads(raw)
            result.exposures = catalog_exposures(cat, schemas, files[-1])
            targets = [*result.exposures, *(claims or [])]
            if probe and targets:
                cols = json.loads(self._psql(name, COLUMNS + ";", "-v", f"schemas={arr}") or "null")
                result.probes = self._probe(name, cat, cols or [], targets)
        finally:
            subprocess.run(["docker", "rm", "-f", name], capture_output=True)
        return result

    def _probe(
        self,
        name: str,
        cat: dict[str, Any],
        cols: list[dict[str, Any]],
        exposures: list[DataExposure],
    ) -> list[Probe]:
        kinds = {f"{r['schema']}.{r['name']}": r["kind"] for r in cat["relations"]}
        sources: dict[str, list[str]] = {}
        for d in cat["view_sources"]:
            sources.setdefault(f"{d['vschema']}.{d['vname']}", []).append(
                f"{d['tschema']}.{d['tname']}"
            )
        required: dict[str, list[dict[str, Any]]] = {}
        for c in cols:
            required.setdefault(f"{c['schema']}.{c['name']}", []).append(c)
        wanted = sorted(
            {(e.resource, e.role, op) for e in exposures for op in e.ops if op in PROBE_OPS}
        )
        out: list[Probe] = []
        for resource, role, op in wanted:
            is_view = kinds.get(resource) == "v"
            if op == "insert" and is_view:
                out.append(Probe(resource, role, op, "inconclusive", "insert through a view"))
                continue
            row = _row(resource, required.get(resource, []))
            if row is None:
                out.append(Probe(resource, role, op, "inconclusive", "no value for a column"))
                continue
            # PUBLIC is a pseudo-role (SET ROLE public fails with 22023); anon is its weakest member
            as_who = "anon" if role == "public" else role
            claims = json.dumps({"sub": str(uuid.uuid4()), "role": as_who})
            as_role = (
                f"set local role {as_who};\n"
                f"select set_config('request.jwt.claims', {_lit(claims)}, true),"
                f" set_config('request.jwt.claim.sub', {_lit(json.loads(claims)['sub'])}, true),"
                f" set_config('request.jwt.claim.role', {_lit(as_who)}, true);\n"
            )
            if op == "insert":
                sql = "begin;\nset local session_replication_role = replica;\n" + as_role
                state, _ = self._try(name, sql + f"{row};\nrollback;\n")
                if state is None or state.startswith("23"):
                    out.append(Probe(resource, role, op, "proven", state or "inserted"))
                elif state == "42501":
                    out.append(Probe(resource, role, op, "denied", state))
                else:
                    out.append(Probe(resource, role, op, "inconclusive", state))
                continue
            seeds = sources.get(resource, []) if is_view else [resource]
            seed_rows = [_row(t, required.get(t, [])) for t in seeds]
            if not seeds or any(r is None for r in seed_rows):
                out.append(Probe(resource, role, op, "inconclusive", "cannot seed a row"))
                continue
            sql = "begin;\nset local session_replication_role = replica;\n"
            sql += "".join(f"{r};\n" for r in seed_rows)
            # identifiers come from the sandbox catalog and are quoted by _ident
            sql += as_role + f"select count(*) from {_ident(resource)};\nrollback;\n"  # noqa: S608
            state, stdout = self._try(name, sql)
            visible = [x for x in stdout.split() if x.isdigit()]
            if state is None and visible and int(visible[-1]) > 0:
                out.append(Probe(resource, role, op, "proven", f"{visible[-1]} row(s) visible"))
            elif state == "42501" or (state is None and visible):
                out.append(Probe(resource, role, op, "denied", state or "seeded row not visible"))
            else:
                out.append(Probe(resource, role, op, "inconclusive", state or "no result"))
        return out


def _quote(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def _ident(resource: str) -> str:
    return ".".join(_quote(p) for p in resource.split(".", 1))


def _lit(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _value(c: dict[str, Any]) -> str | None:
    t, cat = c["type"], c["category"]
    if c["typtype"] == "e":
        return _lit(c["first_label"]) if c["first_label"] is not None else None
    if t == "uuid":
        return "gen_random_uuid()"
    if t in {"json", "jsonb"}:
        return "'{}'"
    return {
        "S": "'ag-probe'",
        "N": "1",
        "B": "true",
        "D": "now()",
        "A": "'{}'",
        "I": "'127.0.0.1'",
    }.get(cat)


def _row(resource: str, required: list[dict[str, Any]]) -> str | None:
    """``insert`` of one row filling every NOT NULL column without a default."""
    values = [_value(c) for c in required]
    if any(v is None for v in values):
        return None
    if not required:
        return f"insert into {_ident(resource)} default values"
    names = ", ".join(_quote(c["col"]) for c in required)
    # quoted catalog identifiers and fixed literals only
    return f"insert into {_ident(resource)} ({names}) values ({', '.join(map(str, values))})"  # noqa: S608


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
            same = [
                (q["cmd"].lower(), q["roles"], q["permissive"] == "PERMISSIVE", q["qual"])
                for q in cat["policies"]
                if (q["schema"], q["name"]) == (p["schema"], p["name"])
            ]
            out += [
                DataExposure(
                    resource=resource,
                    role=x,
                    ops=ops & ALL_PRIVS,
                    reason=write_reason(cmd, x, readable_by(x, same)),
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
