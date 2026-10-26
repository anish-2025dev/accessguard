"""Supabase RLS and grants, statically (FR-3.8; PLAN.md §2 component B).

Migrations (``supabase/migrations/*.sql`` in filename order, else ``supabase/schemas/*.sql``)
are parsed with pglast (libpg_query, the PostgreSQL parser; nothing is executed) and replayed
into a small catalog: tables with their RLS flags and policies, grants and revokes, and views.
Checks in the spirit of Supabase's splinter lints (https://github.com/supabase/splinter):

* ``rls_disabled``: a table in an API-exposed schema without RLS. Supabase grants ``anon`` and
  ``authenticated`` all table privileges in ``public`` by default
  (https://supabase.com/docs/guides/database/postgres/row-level-security), so every privilege
  not explicitly revoked is reachable through the Data API. (splinter 0013)
* ``policy_true_write``: a permissive INSERT/UPDATE/DELETE/ALL policy for anon, authenticated
  or public whose USING / WITH CHECK is the literal ``true``. (splinter 0024)
* ``security_definer_view``: a view in an exposed schema without ``security_invoker`` reading an
  RLS-protected table; it runs as its owner and bypasses RLS. (splinter 0010)
* ``null_fail_open`` (AG-DATA-002, heuristic): a policy whose ownership test is OR-ed with an
  ``IS NULL`` test, or compares ``coalesce(...)`` on both sides, so NULL rows or anonymous
  callers pass.

The optional sandbox (``packages/sandbox``) replays the same migrations in a network-less
Postgres for the cases static replay cannot model; this module never needs it.
"""

from __future__ import annotations

import posixpath
import re
import tomllib
from collections.abc import Iterable
from dataclasses import dataclass, field

from pglast import ast as pg
from pglast import enums, parse_sql
from pglast.stream import RawStream

from authgraph.facts.models import DataExposure, Loc
from authgraph.workspace.tree import SourceTree

API_ROLES = ("anon", "authenticated")
ALL_PRIVS = frozenset({"select", "insert", "update", "delete"})
WRITE_CMDS = frozenset({"insert", "update", "delete", "all"})
DEFAULT_EXPOSED = ("public", "graphql_public")


@dataclass
class Policy:
    name: str
    cmd: str
    roles: list[str]
    permissive: bool
    using: str | None
    check: str | None
    loc: Loc


@dataclass
class Table:
    schema: str
    name: str
    loc: Loc
    # False after CREATE TABLE; None (unknown) for a table no migration created, e.g. one made
    # in the dashboard before the migrations start. Unknown is never reported as disabled.
    rls: bool | None = False
    policies: dict[str, Policy] = field(default_factory=dict)
    # role -> privileges explicitly granted (beyond Supabase's defaults) / revoked
    granted: dict[str, set[str]] = field(default_factory=dict)
    revoked: dict[str, set[str]] = field(default_factory=dict)

    @property
    def key(self) -> str:
        return f"{self.schema}.{self.name}"


@dataclass
class View:
    schema: str
    name: str
    loc: Loc
    security_invoker: bool
    sources: list[tuple[str, str]]


@dataclass
class Catalog:
    tables: dict[tuple[str, str], Table] = field(default_factory=dict)
    views: dict[tuple[str, str], View] = field(default_factory=dict)
    # schema -> role -> privileges revoked by ALTER DEFAULT PRIVILEGES
    default_revoked: dict[str, dict[str, set[str]]] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    files: int = 0


def migration_files(tree: SourceTree) -> list[str]:
    paths = sorted(tree.paths())
    migs = [p for p in paths if re.search(r"(^|/)supabase/migrations/[^/]+\.sql$", p)]
    if migs:
        return sorted(migs, key=posixpath.basename)
    return [p for p in paths if re.search(r"(^|/)supabase/schemas/.+\.sql$", p)]


def exposed_schemas(tree: SourceTree) -> tuple[str, ...]:
    """``[api] schemas`` from supabase/config.toml (https://supabase.com/docs/guides/local-
    development/cli/config#api.schemas), else Supabase's default."""
    for p in tree.paths():
        if p.endswith("supabase/config.toml"):
            try:
                cfg = tomllib.loads(tree.read(p).decode("utf-8", "replace"))
            except tomllib.TOMLDecodeError:
                break
            schemas = cfg.get("api", {}).get("schemas")
            if isinstance(schemas, list) and all(isinstance(s, str) for s in schemas):
                return tuple(schemas)
            break
    return DEFAULT_EXPOSED


def _name(rv: pg.RangeVar | None) -> tuple[str, str]:
    if rv is None:
        return ("public", "")
    return (rv.schemaname or "public", rv.relname or "")


def _sql(node: pg.Node | None) -> str | None:
    return str(RawStream()(node)) if node is not None else None


def _roles(specs: tuple[pg.RoleSpec, ...] | None) -> list[str]:
    out = []
    for r in specs or ():
        if r.roletype == enums.RoleSpecType.ROLESPEC_PUBLIC:
            out.append("public")
        elif r.rolename:
            out.append(r.rolename)
    return out or ["public"]


class _Replay:
    def __init__(self, cat: Catalog) -> None:
        self.cat = cat

    def table(self, key: tuple[str, str], loc: Loc) -> Table:
        t = self.cat.tables.get(key)
        if t is None:  # ALTER of a table created outside the migrations (e.g. auth.users)
            t = Table(key[0], key[1], loc, rls=None)
            self.cat.tables[key] = t
        return t

    def apply(self, stmt: object, loc: Loc) -> None:
        if isinstance(stmt, pg.CreateStmt):
            key = _name(stmt.relation)
            if key not in self.cat.tables:
                t = Table(key[0], key[1], loc)
                for role, privs in self.cat.default_revoked.get(key[0], {}).items():
                    t.revoked.setdefault(role, set()).update(privs)
                self.cat.tables[key] = t
        elif isinstance(stmt, pg.AlterTableStmt) and stmt.relation is not None:
            key = _name(stmt.relation)
            for cmd in stmt.cmds or ():
                sub = getattr(cmd, "subtype", None)
                if sub == enums.AlterTableType.AT_EnableRowSecurity:
                    self.table(key, loc).rls = True
                elif sub == enums.AlterTableType.AT_DisableRowSecurity:
                    self.table(key, loc).rls = False
        elif isinstance(stmt, pg.RenameStmt) and stmt.relation is not None and stmt.newname:
            old = _name(stmt.relation)
            if stmt.renameType == enums.ObjectType.OBJECT_TABLE and old in self.cat.tables:
                t = self.cat.tables.pop(old)
                t.name = stmt.newname
                self.cat.tables[(t.schema, t.name)] = t
        elif isinstance(stmt, pg.CreatePolicyStmt) and stmt.policy_name:
            t = self.table(_name(stmt.table), loc)
            t.policies[stmt.policy_name] = Policy(
                stmt.policy_name,
                (stmt.cmd_name or "all").lower(),
                _roles(stmt.roles),
                bool(stmt.permissive),
                _sql(stmt.qual),
                _sql(stmt.with_check),
                loc,
            )
        elif isinstance(stmt, pg.AlterPolicyStmt) and stmt.policy_name:
            t = self.table(_name(stmt.table), loc)
            p = t.policies.get(stmt.policy_name)
            if p is not None:
                if stmt.roles:
                    p.roles = _roles(stmt.roles)
                if stmt.qual is not None:
                    p.using = _sql(stmt.qual)
                if stmt.with_check is not None:
                    p.check = _sql(stmt.with_check)
                p.loc = loc
        elif isinstance(stmt, pg.DropStmt):
            self.drop(stmt)
        elif isinstance(stmt, pg.GrantStmt):
            self.grant(stmt)
        elif isinstance(stmt, pg.AlterDefaultPrivilegesStmt):
            self.default_privileges(stmt)
        elif isinstance(stmt, pg.ViewStmt):
            key = _name(stmt.view)
            invoker = any(
                o.defname == "security_invoker" and _truthy(o.arg) for o in stmt.options or ()
            )
            self.cat.views[key] = View(key[0], key[1], loc, invoker, _sources(stmt.query))

    def drop(self, stmt: pg.DropStmt) -> None:
        for obj in stmt.objects or ():
            names = [s.sval for s in obj] if isinstance(obj, tuple) else []
            if stmt.removeType == enums.ObjectType.OBJECT_POLICY and len(names) >= 2:
                table = (names[-3], names[-2]) if len(names) >= 3 else ("public", names[-2])
                t = self.cat.tables.get(table)
                if t is not None:
                    t.policies.pop(names[-1], None)
            elif stmt.removeType == enums.ObjectType.OBJECT_TABLE and names:
                key = (names[-2], names[-1]) if len(names) >= 2 else ("public", names[-1])
                self.cat.tables.pop(key, None)
            elif stmt.removeType == enums.ObjectType.OBJECT_VIEW and names:
                key = (names[-2], names[-1]) if len(names) >= 2 else ("public", names[-1])
                self.cat.views.pop(key, None)

    def _privs(self, stmt: pg.GrantStmt) -> set[str]:
        if not stmt.privileges:  # ALL [PRIVILEGES]
            return set(ALL_PRIVS)
        return {p.priv_name.lower() for p in stmt.privileges if p.priv_name} & ALL_PRIVS

    def grant(self, stmt: pg.GrantStmt) -> None:
        if stmt.objtype != enums.ObjectType.OBJECT_TABLE:
            return
        privs = self._privs(stmt)
        roles = _roles(stmt.grantees)
        tables: list[Table] = []
        if stmt.targtype == enums.GrantTargetType.ACL_TARGET_ALL_IN_SCHEMA:
            schemas = {s.sval for s in stmt.objects or () if isinstance(s, pg.String)}
            tables = [t for t in self.cat.tables.values() if t.schema in schemas]
        else:
            # A grant on a view, or on a relation no migration created, says nothing about RLS:
            # it must not invent a table (pilot false positive: GRANT SELECT ON a view).
            tables = [
                self.cat.tables[_name(o)]
                for o in stmt.objects or ()
                if isinstance(o, pg.RangeVar) and _name(o) in self.cat.tables
            ]
        for t in tables:
            for role in roles:
                if stmt.is_grant:
                    t.granted.setdefault(role, set()).update(privs)
                    t.revoked.get(role, set()).difference_update(privs)
                else:
                    t.revoked.setdefault(role, set()).update(privs)
                    t.granted.get(role, set()).difference_update(privs)

    def default_privileges(self, stmt: pg.AlterDefaultPrivilegesStmt) -> None:
        action = stmt.action
        if action is None or action.objtype != enums.ObjectType.OBJECT_TABLE or action.is_grant:
            return
        schemas = ["public"]
        for opt in stmt.options or ():
            if opt.defname == "schemas" and isinstance(opt.arg, tuple):
                schemas = [s.sval for s in opt.arg if isinstance(s, pg.String) and s.sval]
        for s in schemas:
            for role in _roles(action.grantees):
                self.cat.default_revoked.setdefault(s, {}).setdefault(role, set()).update(
                    self._privs(action)
                )


def _truthy(arg: object) -> bool:
    v = getattr(arg, "sval", None) or getattr(arg, "boolval", None)
    if v is None and arg is None:
        return True  # `WITH (security_invoker)` without a value
    return str(v).lower() in {"true", "on", "1", "yes"}


def _sources(query: object) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []

    def visit(n: object) -> None:
        if isinstance(n, pg.RangeVar):
            out.append(_name(n))
        elif isinstance(n, pg.Node):
            for attr in n:
                visit(getattr(n, attr))
        elif isinstance(n, tuple):
            for x in n:
                visit(x)

    visit(query)
    return out


def _line(text: str, offset: int) -> int:
    return text.encode("utf-8")[: max(offset, 0)].decode("utf-8", "replace").count("\n") + 1


def build_catalog(tree: SourceTree) -> Catalog:
    cat = Catalog()
    rp = _Replay(cat)
    for path in migration_files(tree):
        text = tree.read(path).decode("utf-8", "replace")
        cat.files += 1
        try:
            stmts = parse_sql(text)
        except Exception as e:
            cat.errors.append(f"{path}: {str(e).splitlines()[0][:160]}")
            continue
        for raw in stmts:
            loc = Loc(path=path, line=_line(text, raw.stmt_location or 0) + _lead(text, raw))
            rp.apply(raw.stmt, loc)
    return cat


def _lead(text: str, raw: object) -> int:
    """Statements start after leading blank lines and comments; point at the keyword."""
    start = getattr(raw, "stmt_location", 0) or 0
    chunk = text.encode("utf-8")[start : start + 4000].decode("utf-8", "replace")
    n = 0
    for line in chunk.splitlines():
        s = line.strip()
        if s and not s.startswith("--"):
            break
        n += 1
    return n


NULL_OR = re.compile(r"\bIS\s+NULL\b", re.I)
AUTH_FN = re.compile(r"\bauth\.(uid|jwt|role|email)\s*\(", re.I)
COALESCE_BOTH = re.compile(r"coalesce\s*\(.*\)\s*(=|<>|!=)\s*coalesce\s*\(", re.I | re.S)


def fails_open(expr: str | None) -> bool:
    """Can the policy pass because the principal is NULL (anonymous caller or orphan row)?

    ``owner = auth.uid() OR owner IS NULL`` and ``auth.uid() IS NULL OR ...`` do; a NULL test in
    an OR branch that also requires ``col = auth.uid()`` does not, because that comparison is
    NULL for an anonymous caller and the branch can never be TRUE. The expression is parsed with
    pglast and expanded into OR branches (pglast 8.7 ``BoolExpr``/``NullTest``/``A_Expr``)."""
    if not expr:
        return False
    if COALESCE_BOTH.search(expr) and AUTH_FN.search(expr):
        return True
    if not (re.search(r"\bOR\b", expr, re.I) and NULL_OR.search(expr) and AUTH_FN.search(expr)):
        return False
    try:
        node = parse_sql(f"select {expr}")[0].stmt.targetList[0].val  # type: ignore[union-attr]
    except Exception:
        return True
    branches = _branches(node)
    if branches is None:
        return True
    auth_cols = _auth_columns(node)
    for conj in branches:
        null_test = any(
            isinstance(a, pg.NullTest)
            and a.nulltesttype == enums.NullTestType.IS_NULL
            and (_mentions_auth(a.arg) or _column(a.arg) in auth_cols)
            for a in conj
        )
        if null_test and not any(_requires_principal(a) for a in conj):
            return True
    return False


def _deparse(node: object) -> str:
    try:
        return str(RawStream()(node)) if isinstance(node, pg.Node) else ""
    except Exception:
        return ""


def _mentions_auth(node: object) -> bool:
    return bool(AUTH_FN.search(_deparse(node)))


def _column(node: object) -> str | None:
    if isinstance(node, pg.ColumnRef) and node.fields:
        last = node.fields[-1]
        return getattr(last, "sval", None)
    return None


def _branches(node: object, limit: int = 64) -> list[list[object]] | None:
    """OR branches (each a list of AND-ed atoms); None when the expansion is too large."""
    if isinstance(node, pg.BoolExpr) and node.boolop == enums.BoolExprType.OR_EXPR:
        out: list[list[object]] = []
        for a in node.args or ():
            sub = _branches(a, limit)
            if sub is None:
                return None
            out += sub
        return out if len(out) <= limit else None
    if isinstance(node, pg.BoolExpr) and node.boolop == enums.BoolExprType.AND_EXPR:
        acc: list[list[object]] = [[]]
        for a in node.args or ():
            sub = _branches(a, limit)
            if sub is None or len(acc) * len(sub) > limit:
                return None
            acc = [x + y for x in acc for y in sub]
        return acc
    return [[node]]


def _auth_columns(node: object) -> set[str]:
    """Columns compared with an auth function anywhere in the expression."""
    out: set[str] = set()

    def walk(n: object) -> None:
        if isinstance(n, pg.A_Expr):
            sides = (n.lexpr, n.rexpr)
            if any(_mentions_auth(x) for x in sides):
                out.update(c for c in map(_column, sides) if c)
        if isinstance(n, pg.Node):
            for name in n:  # pglast Node iterates its attribute names
                v = getattr(n, name)
                for c in v if isinstance(v, tuple) else (v,):
                    walk(c)

    walk(node)
    return out


def _requires_principal(atom: object) -> bool:
    """An AND-ed atom that is never TRUE when the auth function returns NULL."""
    if isinstance(atom, pg.NullTest):
        return atom.nulltesttype == enums.NullTestType.IS_NOT_NULL and _mentions_auth(atom.arg)
    if isinstance(atom, pg.A_Expr) and atom.kind == enums.A_Expr_Kind.AEXPR_OP:
        op = atom.name[-1].sval if atom.name else ""
        sides = (atom.lexpr, atom.rexpr)
        return op in {"=", "<>", "!=", "<", ">", "<=", ">="} and any(
            _mentions_auth(x) and "coalesce" not in _deparse(x).lower() for x in sides
        )
    return False


def readable_by(role: str, policies: Iterable[tuple[str, list[str], bool, str | None]]) -> bool:
    """Some permissive SELECT/ALL policy lets ``role`` read every row (``using (true)``).

    ``policies`` are ``(cmd, roles, permissive, using)``; ``public`` covers every role."""
    return any(
        cmd in {"select", "all"}
        and permissive
        and (role in roles or "public" in roles)
        and is_true(using)
        for cmd, roles, permissive, using in policies
    )


def write_reason(cmd: str, role: str, readable: bool) -> str:
    """``write_only_insert`` for an insert-anything policy on rows ``role`` cannot read back (a
    contact form or order drop box: spam, not a data leak); ``policy_true_write`` otherwise."""
    return "write_only_insert" if cmd == "insert" and not readable else "policy_true_write"


def _write_reason(cmd: str, role: str, policies: Iterable[Policy]) -> str:
    rows = [(p.cmd, p.roles, p.permissive, p.using) for p in policies]
    return write_reason(cmd, role, readable_by(role, rows))


def is_true(expr: str | None) -> bool:
    return expr is not None and expr.strip().strip("()").strip().lower() == "true"


def exposures(cat: Catalog, exposed: tuple[str, ...]) -> list[DataExposure]:
    out: list[DataExposure] = []
    for t in cat.tables.values():
        if t.schema not in exposed:
            continue
        if t.rls is False:
            for role in API_ROLES:
                privs = (set(ALL_PRIVS) | t.granted.get(role, set())) - t.revoked.get(role, set())
                if privs:
                    out.append(
                        DataExposure(
                            resource=t.key,
                            role=role,
                            ops=privs,
                            reason="rls_disabled",
                            loc=t.loc,
                            detail="row level security is not enabled",
                        )
                    )
            continue
        for p in t.policies.values():
            roles = [r for r in p.roles if r in {"anon", "authenticated", "public"}]
            if not roles or not p.permissive:
                continue
            ops: set[str] = {"insert", "update", "delete"} if p.cmd == "all" else {p.cmd}
            ops &= ALL_PRIVS
            if p.cmd in WRITE_CMDS:
                opens = (
                    is_true(p.check)
                    or (p.cmd == "insert" and p.check is None and is_true(p.using))
                    or (p.cmd in {"update", "delete", "all"} and is_true(p.using))
                )
                if opens:
                    for role in roles:
                        out.append(
                            DataExposure(
                                resource=t.key,
                                role=role,
                                ops=set(ops),
                                reason=_write_reason(p.cmd, role, t.policies.values()),
                                loc=p.loc,
                                detail=f'policy "{p.name}" allows every row',
                            )
                        )
            for expr in (p.using, p.check):
                if fails_open(expr):
                    for role in roles:
                        out.append(
                            DataExposure(
                                resource=t.key,
                                role=role,
                                ops={"select"} if p.cmd == "select" else set(ops),
                                reason="null_fail_open",
                                loc=p.loc,
                                detail=f'policy "{p.name}": {expr}'[:300],
                            )
                        )
                    break
    for v in cat.views.values():
        if v.schema not in exposed or v.security_invoker:
            continue
        protected = [s for s in v.sources if (t2 := cat.tables.get(s)) is not None and t2.rls]
        if protected:
            out.append(
                DataExposure(
                    resource=f"{v.schema}.{v.name}",
                    role="anon",
                    ops={"select"},
                    reason="security_definer_view",
                    loc=v.loc,
                    detail="view runs as its owner and bypasses RLS on "
                    + ", ".join(f"{a}.{b}" for a, b in protected),
                )
            )
    return out


def analyze_supabase(tree: SourceTree) -> tuple[list[DataExposure], list[str]]:
    if not migration_files(tree):
        return [], []
    cat = build_catalog(tree)
    return exposures(cat, exposed_schemas(tree)), cat.errors
