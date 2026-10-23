"""Python ``ast`` summarizer: one ``FileSummary`` per file.

Parses only; never imports or runs code (ADR 005).
"""

from __future__ import annotations

import ast
import json
import re
from typing import Any

from authgraph.lang.python.summary import (
    Assign,
    ClassInfo,
    ExceptInfo,
    FileSummary,
    Function,
    Import,
    MassAssign,
    MethodCall,
    Param,
    RaiseInfo,
    SinkInfo,
    Value,
)

ROUTER_METHODS = frozenset(
    {
        "include_router",
        "mount",
        "add_api_route",
        "add_route",
        "add_api_websocket_route",
        "add_websocket_route",
        "host",
    }
)
ROLE_ATTRS = frozenset(
    {
        "role",
        "roles",
        "is_superuser",
        "is_admin",
        "is_staff",
        "scopes",
        "permissions",
        "groups",
        "superuser",
        "admin",
        "user_role",
        "is_owner",
    }
)
OWNER_ATTRS = frozenset(
    {"owner_id", "user_id", "owner", "author_id", "created_by", "created_by_id", "account_id"}
)
# Names that hold the authenticated caller (not `db_user`, which is a fetched record).
PRINCIPAL_ROOT = re.compile(
    r"^(current_?\w*|user|me|principal|account|auth_?user|requester|viewer|caller|actor|"
    r"identity|session_?user|token_?data)$",
    re.I,
)
PRINCIPAL_HINTS = ("user", "principal", "account", "member", "me", "owner", "subject")
TOKEN_FUNCS = frozenset(
    {
        "decode_token",
        "verify_token",
        "verify_id_token",
        "verify_jwt",
        "decode_jwt",
        "decode_access_token",
        "verify_access_token",
        "validate_token",
        "get_user_from_token",
        "verify_session",
        "get_user",  # supabase.auth.get_user(jwt)
    }
)
AUTH_EXC_NAME = re.compile(
    r"(unauthori[sz]ed|forbidden|permission|notauthenticated|authentication|credential|"
    r"accessdenied|auth)",
    re.I,
)
LOG_ROOTS = frozenset({"logger", "logging", "log", "print", "warnings", "_logger", "LOGGER"})
READ_TERMINALS = frozenset({"first", "all", "one", "one_or_none", "scalar", "scalars", "get"})


def dotted(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = dotted(node.value)
        return f"{base}.{node.attr}" if base else None
    return None


def call_dotted(node: ast.AST) -> str | None:
    return dotted(node.func) if isinstance(node, ast.Call) else None


def _callee(call: ast.Call) -> str | None:
    """Callee name, seeing through generic subscripts: ``FastAPIUsers[User, ID](...)``."""
    f = call.func
    if isinstance(f, ast.Subscript):
        f = f.value
    return dotted(f)


def to_value(node: ast.AST | None) -> Value | None:
    if node is None:
        return None
    line = getattr(node, "lineno", 0)
    if isinstance(node, ast.Constant) and isinstance(node.value, str | int | bool):
        return Value(kind="const", const=node.value, line=line)
    d = dotted(node)
    if d is not None:
        return Value(kind="name", dotted=d, line=line)
    if isinstance(node, ast.Call):
        return Value(
            kind="call",
            dotted=_callee(node),
            args=[v for a in node.args if (v := to_value(a)) is not None],
            kwargs={
                k.arg: v for k in node.keywords if k.arg and (v := to_value(k.value)) is not None
            },
            line=line,
        )
    if isinstance(node, ast.List | ast.Tuple | ast.Set):
        return Value(
            kind="list", items=[v for e in node.elts if (v := to_value(e)) is not None], line=line
        )
    if isinstance(node, ast.Subscript):
        sl = node.slice
        elts = sl.elts if isinstance(sl, ast.Tuple) else [sl]
        return Value(
            kind="subscript",
            dotted=dotted(node.value),
            items=[v for e in elts if (v := to_value(e)) is not None],
            line=line,
        )
    if isinstance(node, ast.JoinedStr):
        parts: list[Value] = []
        for p in node.values:
            if isinstance(p, ast.Constant):
                parts.append(Value(kind="const", const=str(p.value)))
            elif isinstance(p, ast.FormattedValue):
                parts.append(to_value(p.value) or Value(kind="other"))
        return Value(kind="fstring", items=parts, line=line)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = to_value(node.left), to_value(node.right)
        return Value(
            kind="fstring", items=[left or Value(kind="other"), right or Value(kind="other")]
        )
    return Value(kind="other", line=line)


# --- boolean formulas for guard predicates (consumed by the Z3 check) ----------------------------


def _atom(node: ast.expr) -> list[Any]:
    if isinstance(node, ast.Compare) and len(node.ops) == 1:
        op, left, right = node.ops[0], node.left, node.comparators[0]
        neg = {ast.NotEq: ast.Eq, ast.IsNot: ast.Is, ast.NotIn: ast.In}
        for bad, good in neg.items():
            if isinstance(op, bad):
                return ["not", _atom(ast.Compare(left=left, ops=[good()], comparators=[right]))]
        if isinstance(op, ast.Eq | ast.Is):
            a, b = sorted([ast.unparse(left), ast.unparse(right)])
            return ["atom", f"{a} {'==' if isinstance(op, ast.Eq) else 'is'} {b}"]
    return ["atom", ast.unparse(node)]


def formula(node: ast.expr) -> list[Any]:
    if isinstance(node, ast.BoolOp):
        return ["and" if isinstance(node.op, ast.And) else "or", *[formula(v) for v in node.values]]
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        return ["not", formula(node.operand)]
    return _atom(node)


def _exits(body: list[ast.stmt]) -> bool:
    """Does every path through ``body`` leave the enclosing block (return/raise/...)?"""
    if not body:
        return False
    last = body[-1]
    if isinstance(last, ast.Return | ast.Raise | ast.Continue | ast.Break):
        return True
    if isinstance(last, ast.If):
        return _exits(last.body) and _exits(last.orelse)
    return False


def _conj(conds: list[list[Any]]) -> str | None:
    if not conds:
        return None
    return json.dumps(conds[0] if len(conds) == 1 else ["and", *conds])


# --- helpers ---------------------------------------------------------------------------------


def _status_of(node: ast.AST | None) -> int | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, int):
        return node.value
    d = dotted(node) if node is not None else None
    if d:
        m = re.search(r"HTTP_(\d{3})", d)
        if m:
            return int(m.group(1))
    return None


def _exc_status(call: ast.Call) -> int | None:
    for kw in call.keywords:
        if kw.arg == "status_code":
            return _status_of(kw.value)
    if call.args:
        return _status_of(call.args[0])
    return None


def _root_name(node: ast.AST) -> str | None:
    while isinstance(node, ast.Attribute | ast.Subscript | ast.Call):
        node = node.func if isinstance(node, ast.Call) else node.value
    return node.id if isinstance(node, ast.Name) else None


def _names_in(node: ast.AST) -> set[str]:
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


def _chain(call: ast.Call) -> list[ast.Call]:
    """``a.query(M).filter(x).first()`` -> [query(...), filter(...), first(...)] (inner first)."""
    out: list[ast.Call] = []
    node: ast.AST = call
    while isinstance(node, ast.Call):
        out.append(node)
        f = node.func
        node = f.value if isinstance(f, ast.Attribute) else f
        while isinstance(node, ast.Attribute):
            node = node.value
            if isinstance(node, ast.Call):
                break
    return list(reversed(out))


def _method(call: ast.Call) -> str:
    return call.func.attr if isinstance(call.func, ast.Attribute) else (dotted(call.func) or "")


class _FunctionVisitor:
    """Collects guard features, raise conditions, sinks and mass assignment for one function."""

    def __init__(self, fn: Function, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        self.fn = fn
        self.node = node
        self.exc_vars: dict[str, int | None] = {}
        self.calls: list[str] = []

    def run(self) -> Function:
        for p in self.fn.params:
            if p.name.lower() in {"authorization", "token", "credentials", "api_key"}:
                self.fn.reads_authorization = True
        self._block(self.node.body, [], False)
        self._scan_expressions()
        self.fn.calls = sorted(set(self.calls))[:80]
        checks = [r.line for r in self.fn.raises if r.status in (401, 403)]
        self.fn.first_check_line = min(checks) if checks else None
        return self.fn

    # statements, tracking the path condition for raises
    def _block(self, body: list[ast.stmt], conds: list[list[Any]], in_except: bool) -> None:
        conds = list(conds)
        for st in body:
            self._stmt(st, conds, in_except)
            # `if user: return user` -> everything after it runs only when `not user`.
            if isinstance(st, ast.If) and _exits(st.body) and not _exits(st.orelse):
                conds.append(["not", formula(st.test)])
            elif isinstance(st, ast.If) and _exits(st.orelse) and not _exits(st.body):
                conds.append(formula(st.test))

    def _stmt(self, st: ast.stmt, conds: list[list[Any]], in_except: bool) -> None:
        if isinstance(st, ast.If):
            c = formula(st.test)
            self._block(st.body, [*conds, c], in_except)
            self._block(st.orelse, [*conds, ["not", c]], in_except)
        elif isinstance(st, ast.Try | ast.TryStar):
            self._block(st.body, conds, in_except)
            for h in st.handlers:
                self.fn.excepts.append(
                    ExceptInfo(
                        exc=self._exc_names(h.type), body=self._handler_kind(h), line=h.lineno
                    )
                )
                # Rejection inside an except handler is conditional on the exception.
                exc_atom = ["atom", "except " + "|".join(self._exc_names(h.type))]
                self._block(h.body, [*conds, exc_atom], True)
            self._block(st.orelse, conds, in_except)
            self._block(st.finalbody, conds, in_except)
        elif isinstance(st, ast.For | ast.AsyncFor | ast.While | ast.With | ast.AsyncWith):
            self._block(st.body, conds, in_except)
            self._block(getattr(st, "orelse", []), conds, in_except)
        elif isinstance(st, ast.Raise):
            self._raise(st, conds, in_except)
        elif isinstance(st, ast.Assign) and isinstance(st.value, ast.Call):
            d = call_dotted(st.value) or ""
            if d.split(".")[-1] == "HTTPException" or AUTH_EXC_NAME.search(d.split(".")[-1]):
                for t in st.targets:
                    if isinstance(t, ast.Name):
                        self.exc_vars[t.id] = _exc_status(st.value)
        elif isinstance(st, ast.Return):
            if st.value is None or (isinstance(st.value, ast.Constant) and st.value.value is None):
                self.fn.returns_none = True
            elif isinstance(st.value, ast.Name):
                self.fn.return_names.append(st.value.id)
                self.fn.return_conds[st.value.id] = _conj(conds)
            elif isinstance(st.value, ast.IfExp):  # return a if flag else b
                c = formula(st.value.test)
                for branch, cond in ((st.value.body, c), (st.value.orelse, ["not", c])):
                    if isinstance(branch, ast.Name):
                        self.fn.return_names.append(branch.id)
                        self.fn.return_conds[branch.id] = _conj([*conds, cond])
            elif isinstance(st.value, ast.Call) and (callee := _callee(st.value)):
                self.fn.return_calls.append(callee)
                arg = st.value.args[0] if st.value.args else None
                if callee.split(".")[-1] in ("Depends", "Security") and isinstance(arg, ast.Name):
                    self.fn.return_names.append(arg.id)  # return Depends(checker)
                    self.fn.return_conds[arg.id] = _conj(conds)
        elif isinstance(st, ast.Match):
            for case in st.cases:
                self._block(case.body, conds, in_except)

    def _raise(self, st: ast.Raise, conds: list[list[Any]], in_except: bool) -> None:
        exc, status = "", None
        if isinstance(st.exc, ast.Call):
            exc = call_dotted(st.exc) or ""
            status = _exc_status(st.exc)
        elif isinstance(st.exc, ast.Name):
            exc = st.exc.id
            status = self.exc_vars.get(st.exc.id)
        elif st.exc is None:
            exc = "<reraise>"
        short = exc.split(".")[-1]
        if status is None and short != "HTTPException" and AUTH_EXC_NAME.search(short):
            status = 403 if re.search(r"forbidden|permission|denied", short, re.I) else 401
        self.fn.raises.append(
            RaiseInfo(
                status=status, exc=exc, condition=_conj(conds), in_except=in_except, line=st.lineno
            )
        )

    @staticmethod
    def _exc_names(t: ast.expr | None) -> list[str]:
        if t is None:
            return ["<bare>"]
        if isinstance(t, ast.Tuple):
            return [dotted(e) or "?" for e in t.elts]
        return [dotted(t) or "?"]

    @staticmethod
    def _handler_kind(h: ast.ExceptHandler) -> Any:
        kinds = set()
        for st in h.body:
            if isinstance(st, ast.Raise):
                return "raise"
            if isinstance(st, ast.Return):
                kinds.add("return")
            elif isinstance(st, ast.Pass):
                kinds.add("pass")
            elif isinstance(st, ast.Expr) and isinstance(st.value, ast.Call):
                root = (call_dotted(st.value) or "").split(".")[0]
                kinds.add("log" if root in LOG_ROOTS else "other")
            elif isinstance(st, ast.Assign | ast.AnnAssign | ast.AugAssign):
                kinds.add("log")
            else:
                kinds.add("other")
        if "other" in kinds:
            return "other"
        if kinds == {"pass"}:
            return "pass"
        if "return" in kinds:
            return "return"
        return "log_only"

    # expression-level features
    def _scan_expressions(self) -> None:
        inner_chain: set[int] = set()
        calls = [n for n in ast.walk(self.node) if isinstance(n, ast.Call)]
        for c in calls:
            for part in _chain(c)[:-1]:
                inner_chain.add(id(part))
        for node in ast.walk(self.node):
            if isinstance(node, ast.Call):
                d = call_dotted(node) or ""
                if d:
                    self.calls.append(d)
                last = d.split(".")[-1]
                if (
                    (last == "decode" and "jwt" in d.lower())
                    or last in TOKEN_FUNCS
                    or ("jwt" in d.lower() and last in {"decode", "verify"})
                ):
                    self.fn.token_decode = True
                if id(node) not in inner_chain:
                    self._sink(node)
                self._mass_assign(node)
            elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                v = node.value.lower()
                if v in {"authorization", "x-api-key", "x-auth-token", "access_token"}:
                    self.fn.reads_authorization = True
                if v in {"admin", "superuser", "administrator"}:
                    self.fn.role_refs.append(v)
            elif isinstance(node, ast.Attribute):
                if node.attr in ROLE_ATTRS:
                    self.fn.role_refs.append(node.attr)
            elif isinstance(node, ast.Compare):
                self._owner_compare(node)
            elif isinstance(node, ast.For):
                self._setattr_loop(node)
        self.fn.role_refs = sorted(set(self.fn.role_refs))

    def _owner_compare(self, node: ast.Compare) -> None:
        """``item.owner_id == user.id`` or ``current_user["username"] != username``."""
        sides = [node.left, *node.comparators]

        def principal(n: ast.AST) -> bool:
            return isinstance(n, ast.Attribute | ast.Subscript) and bool(
                PRINCIPAL_ROOT.match(_root_name(n) or "")
            )

        owner_attr = any(isinstance(n, ast.Attribute) and n.attr in OWNER_ATTRS for n in sides)
        # The other side is request/data derived (a name or a fetched object's field), never a
        # constant: `user.role == "admin"` is a role check, not ownership.
        request_value = any(
            isinstance(n, ast.Name | ast.Attribute | ast.Subscript) and not principal(n)
            for n in sides
        )
        if any(principal(n) for n in sides) and (owner_attr or request_value):
            self.fn.owner_compare = True

    def _sink(self, call: ast.Call) -> None:
        chain = _chain(call)
        methods = [_method(c) for c in chain]
        model: str | None = None
        orm = ""
        if "query" in methods:
            q = chain[methods.index("query")]
            model = dotted(q.args[0]) if q.args else None
            orm = "sqlalchemy.query"
        elif methods and methods[0] in {"select", "delete", "update"} and chain[0].args:
            model = dotted(chain[0].args[0])
            orm = f"sqlalchemy.{methods[0]}"
        elif len(chain) == 1 and methods[0] == "get" and len(call.args) >= 2:
            recv = dotted(call.func.value) if isinstance(call.func, ast.Attribute) else None
            if recv and recv.split(".")[-1] in {"db", "session", "s", "sess", "database"}:
                model = dotted(call.args[0])
                orm = "sqlalchemy.session.get"
        if not orm or model is None:
            return
        kind: Any = "read"
        if "delete" in methods:
            kind = "delete"
        elif "update" in methods or "values" in methods:
            kind = "write"
        names: set[str] = set()
        for c, m in zip(chain, methods, strict=True):
            if m in {"filter", "filter_by", "where", "get"} or orm == "sqlalchemy.session.get":
                args = c.args[1:] if orm == "sqlalchemy.session.get" else c.args
                for a in [*args, *[k.value for k in c.keywords]]:
                    names |= _names_in(a)
        names.discard(model.split(".")[0])
        self.fn.sinks.append(
            SinkInfo(
                kind=kind, orm=orm, model=model, predicate_names=sorted(names), line=call.lineno
            )
        )

    def _dump_source(self, node: ast.AST) -> tuple[str, list[str]] | None:
        """``X.dict()``, ``X.model_dump(exclude={..})``, ``jsonable_encoder(X)`` -> ("X", [..])."""
        if not isinstance(node, ast.Call):
            return None
        m = _method(node)
        if m in {"dict", "model_dump"} and isinstance(node.func, ast.Attribute):
            root = _root_name(node.func.value)
            excluded: list[str] = []
            for kw in node.keywords:
                if kw.arg == "exclude" and isinstance(kw.value, ast.Set | ast.List | ast.Tuple):
                    excluded = [
                        e.value
                        for e in kw.value.elts
                        if isinstance(e, ast.Constant) and isinstance(e.value, str)
                    ]
            return (root, excluded) if root else None
        if m in {"jsonable_encoder", "items"} and node.args:
            return self._dump_source(node.args[0]) or (
                (r, []) if (r := _root_name(node.args[0])) else None
            )
        if m == "items" and isinstance(node.func, ast.Attribute):
            return self._dump_source(node.func.value)
        return None

    def _mass_assign(self, call: ast.Call) -> None:
        m = _method(call)
        src: tuple[str, list[str]] | None = None
        for kw in call.keywords:
            if kw.arg is None:  # Model(**body.dict())
                src = self._dump_source(kw.value)
        if m in {"update", "sqlmodel_update", "model_copy", "copy"} and call.args:
            src = src or self._dump_source(call.args[0])
        if m in {"model_copy", "copy"}:
            for kw in call.keywords:
                if kw.arg == "update":
                    src = src or self._dump_source(kw.value)
        if src:
            self.fn.mass_assign.append(MassAssign(source=src[0], excluded=src[1], line=call.lineno))

    def _setattr_loop(self, node: ast.For) -> None:
        src = self._dump_source(node.iter)
        if src is None and isinstance(node.iter, ast.Call) and _method(node.iter) == "items":
            f = node.iter.func
            if isinstance(f, ast.Attribute):
                src = self._dump_source(f.value)
        if not src:
            return
        for n in ast.walk(node):
            if isinstance(n, ast.Call) and call_dotted(n) == "setattr":
                self.fn.mass_assign.append(
                    MassAssign(source=src[0], excluded=src[1], line=node.lineno)
                )
                return


def _params(args: ast.arguments) -> list[Param]:
    positional = [*args.posonlyargs, *args.args]
    defaults: list[ast.expr | None] = [None] * (len(positional) - len(args.defaults))
    defaults += list(args.defaults)
    out = [
        Param(name=a.arg, annotation=to_value(a.annotation), default=to_value(d))
        for a, d in zip(positional, defaults, strict=True)
    ]
    out += [
        Param(name=a.arg, annotation=to_value(a.annotation), default=to_value(d))
        for a, d in zip(args.kwonlyargs, args.kw_defaults, strict=True)
    ]
    return out


class Summarizer(ast.NodeVisitor):
    def __init__(self, summary: FileSummary) -> None:
        self.s = summary
        self.scope: list[str] = []

    @property
    def qual(self) -> str:
        return ".".join(self.scope)

    def visit_Import(self, node: ast.Import) -> None:
        for a in node.names:
            # `import a.b` binds `a`; `import a.b as x` binds the submodule a.b
            module = a.name if a.asname else a.name.split(".")[0]
            local = a.asname or module
            self.s.imports.append(Import(scope=self.qual, module=module, name=None, asname=local))

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        for a in node.names:
            if a.name == "*":
                self.s.imports.append(
                    Import(
                        scope=self.qual,
                        module=node.module or "",
                        name="*",
                        asname="*",
                        level=node.level,
                    )
                )
                continue
            self.s.imports.append(
                Import(
                    scope=self.qual,
                    module=node.module or "",
                    name=a.name,
                    asname=a.asname or a.name,
                    level=node.level,
                )
            )

    def visit_Assign(self, node: ast.Assign) -> None:
        value = to_value(node.value)
        for t in node.targets:
            if isinstance(t, ast.Name) and value is not None:
                self.s.assigns.append(
                    Assign(scope=self.qual, target=t.id, value=value, line=node.lineno)
                )
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if isinstance(node.target, ast.Name):
            value = to_value(node.value) if node.value is not None else None
            ann = to_value(node.annotation)
            # `CurrentUser: TypeAlias = Annotated[...]` -> the value is the alias
            if value is not None:
                self.s.assigns.append(
                    Assign(
                        scope=self.qual,
                        target=node.target.id,
                        value=value,
                        line=node.lineno,
                        annotation=ann,
                    )
                )
        self.generic_visit(node)

    def visit_TypeAlias(self, node: ast.TypeAlias) -> None:
        value = to_value(node.value)
        if isinstance(node.name, ast.Name) and value is not None:
            self.s.assigns.append(
                Assign(scope=self.qual, target=node.name.id, value=value, line=node.lineno)
            )

    def visit_Expr(self, node: ast.Expr) -> None:
        call = node.value
        if isinstance(call, ast.Await):
            call = call.value
        if isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute):
            recv = dotted(call.func.value)
            if recv and call.func.attr in ROUTER_METHODS:
                self.s.method_calls.append(
                    MethodCall(
                        scope=self.qual,
                        receiver=recv,
                        method=call.func.attr,
                        args=[v for a in call.args if (v := to_value(a)) is not None],
                        kwargs={
                            k.arg: v
                            for k in call.keywords
                            if k.arg and (v := to_value(k.value)) is not None
                        },
                        line=node.lineno,
                    )
                )
        self.generic_visit(node)

    def _function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        self.scope.append(node.name)
        fn = Function(
            qualname=self.qual,
            name=node.name,
            line=node.lineno,
            is_async=isinstance(node, ast.AsyncFunctionDef),
            params=_params(node.args),
            decorators=[v for d in node.decorator_list if (v := to_value(d)) is not None],
            returns=to_value(node.returns),
        )
        self.s.functions[fn.qualname] = _FunctionVisitor(fn, node).run()
        for st in node.body:
            self.visit(st)
        self.scope.pop()

    visit_FunctionDef = _function
    visit_AsyncFunctionDef = _function

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.scope.append(node.name)
        info = ClassInfo(
            name=self.qual, line=node.lineno, bases=[dotted(b) or "?" for b in node.bases]
        )
        for st in node.body:
            if isinstance(st, ast.AnnAssign) and isinstance(st.target, ast.Name):
                info.fields[st.target.id] = to_value(st.value) if st.value is not None else None
            elif isinstance(st, ast.Assign):
                for t in st.targets:
                    if isinstance(t, ast.Name):
                        info.fields[t.id] = to_value(st.value)
            elif isinstance(st, ast.FunctionDef | ast.AsyncFunctionDef):
                info.methods.append(f"{self.qual}.{st.name}")
                self.visit(st)
        self.s.classes[info.name] = info
        self.scope.pop()


_PEP758 = re.compile(rb"^(\s*except\*?\s+)(?!\()([\w.]+(?:\s*,\s*[\w.]+)+)(\s*:)", re.M)


def compat_rewrite(source: bytes) -> bytes:
    """Rewrite PEP 758 unparenthesized ``except A, B:`` (Python 3.14) to ``except (A, B):``.
    Line numbers are preserved."""
    return _PEP758.sub(rb"\1(\2)\3", source)


def module_name_for(path: str) -> tuple[str, bool]:
    """Best-effort dotted module path from a repo-relative file path (resolver refines roots)."""
    parts = path[:-3].split("/") if path.endswith(".py") else path.split("/")
    is_pkg = parts[-1] == "__init__"
    if is_pkg:
        parts = parts[:-1]
    return ".".join(parts), is_pkg


def summarize(path: str, source: bytes, blob_sha: str) -> FileSummary:
    module, is_pkg = module_name_for(path)
    s = FileSummary(path=path, module=module, blob_sha=blob_sha, is_package=is_pkg)
    try:
        tree = ast.parse(source, filename=path)
    except (SyntaxError, ValueError) as e:
        try:  # newer-Python syntax the 3.12 parser rejects (e.g. PEP 758 `except A, B:`)
            tree = ast.parse(compat_rewrite(source), filename=path)
        except (SyntaxError, ValueError):
            s.parse_error = f"{type(e).__name__}: {e}"
            return s
    Summarizer(s).visit(tree)
    return s
