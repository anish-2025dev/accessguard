"""FastAPI router graph, route enumeration and guard closure (FR-3.1, FR-3.2; PLAN.md §6.4).

Static only: the graph is built from summaries (decorators, ``add_api_route``,
``include_router`` prefixes/dependencies, ``mount``, cross-file imports). Anything we cannot
fold to a constant becomes ``<dynamic>``; any auth-looking dependency we cannot resolve makes the
verdict UNKNOWN instead of a guess.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from authgraph.diff.logic import evaluate
from authgraph.facts.models import (
    ENFORCING_KINDS,
    Endpoint,
    GuardKind,
    GuardRef,
    GuardSource,
    Loc,
    OnFail,
    Sink,
    Verdict,
)
from authgraph.guards.config import Config
from authgraph.guards.scoring import (
    AUTHISH_EXTERNAL,
    CONFIRMED,
    NON_GUARD_EXTERNAL,
    auth_raises,
    builtin_external,
    classify,
)
from authgraph.lang.python.resolver import ProjectIndex, Target
from authgraph.lang.python.summary import Function, Value

HTTP_METHODS = frozenset({"get", "post", "put", "patch", "delete", "options", "head", "trace"})
APP_CLASSES = frozenset({"FastAPI"})
ROUTER_CLASSES = frozenset({"APIRouter"})
DEP_CALLS = frozenset({"Depends", "Security"})
PRIVILEGED_FIELDS = frozenset(
    {
        "role",
        "roles",
        "user_role",
        "is_admin",
        "is_superuser",
        "is_staff",
        "permissions",
        "scopes",
        "groups",
        "owner_id",
        "user_id",
        "author_id",
        "tenant_id",
        "org_id",
        "organization_id",
        "is_verified",
    }
)
PRINCIPAL_NAME = re.compile(r"(user|principal|account|member|owner|^me$|subject|identity)", re.I)
MAX_DEP_DEPTH = 8
NodeKey = tuple[str, str, str]  # (path, scope, variable)


@dataclass
class DepUse:
    value: Value  # the dependency expression (Depends arg) or a class for `Depends()`
    path: str
    scope: str
    loc: Loc
    inherited: bool = False


@dataclass
class RouteDecl:
    methods: list[str]
    path: str | None
    handler: Target
    deps: list[DepUse]
    loc: Loc
    file: str
    scope: str


@dataclass
class Include:
    child: NodeKey
    prefix: str | None
    deps: list[DepUse]
    loc: Loc


@dataclass
class Mount:
    child: NodeKey
    path: str | None
    loc: Loc


@dataclass
class Node:
    key: NodeKey
    kind: str  # "app" | "router"
    prefix: str | None
    deps: list[DepUse]
    loc: Loc
    routes: list[RouteDecl] = field(default_factory=list)
    includes: list[Include] = field(default_factory=list)
    mounts: list[Mount] = field(default_factory=list)


@dataclass
class Closure:
    guards: list[GuardRef] = field(default_factory=list)
    unresolved: list[str] = field(default_factory=list)


def _join(*parts: str | None) -> str:
    out = "".join(p if p is not None else "<dynamic>" for p in parts)
    out = re.sub(r"/{2,}", "/", out)
    return out if out.startswith("/") else "/" + out


class FastAPIGraph:
    def __init__(self, index: ProjectIndex, config: Config) -> None:
        self.ix = index
        self.config = config
        self.nodes: dict[NodeKey, Node] = {}
        self._closure_cache: dict[tuple[str, str, str], Closure] = {}
        self._call_sites: dict[tuple[str, str], list[tuple[Value, str, str]]] | None = None
        self._build_nodes()
        self._attach()

    # --- graph construction ----------------------------------------------------------------

    def _loc(self, path: str, line: int) -> Loc:
        s = self.ix.files.get(path)
        return Loc(path=path, line=line, blob_sha=s.blob_sha if s else "")

    def _class_kind(self, t: Target, depth: int = 0) -> str | None:
        if depth > 4:
            return None
        if t.kind == "external":
            last = t.name.split(".")[-1]
            root = t.name.split(".")[0]
            if root in {"fastapi", "starlette"} or "." not in t.name:
                if last in APP_CLASSES:
                    return "app"
                if last in ROUTER_CLASSES:
                    return "router"
            return None
        info = self.ix.klass(t)
        if info is not None:
            for b in info.bases:
                k = self._class_kind(self.ix.resolve(t.path, "", b), depth + 1)
                if k:
                    return k
        return None

    def _build_nodes(self) -> None:
        for path, s in self.ix.files.items():
            for a in s.assigns:
                if a.value.kind != "call" or not a.value.dotted:
                    continue
                kind = self._class_kind(self.ix.resolve(path, a.scope, a.value.dotted))
                if kind is None:
                    continue
                key = (path, a.scope, a.target)
                prefix_v = a.value.kwargs.get("prefix")
                deps = self._dep_list(a.value.kwargs.get("dependencies"), path, a.scope, True)
                deps += self._subclass_deps(self.ix.resolve(path, a.scope, a.value.dotted), a.line)
                self.nodes[key] = Node(
                    key=key,
                    kind=kind,
                    prefix=self.ix.eval_str(path, a.scope, prefix_v) if prefix_v else "",
                    deps=deps,
                    loc=self._loc(path, a.line),
                )

    def _subclass_deps(self, t: Target, line: int, depth: int = 0) -> list[DepUse]:
        """Router subclasses: ``super().__init__(dependencies=[...])`` in ``__init__``."""
        info = self.ix.klass(t)
        if info is None or depth > 4:
            return []
        out: list[DepUse] = []
        init = self.ix.function(Target("function", t.path, f"{t.name}.__init__"))
        if init is not None and init.super_init is not None:
            dv = init.super_init.kwargs.get("dependencies")
            out += self._dep_list(dv, t.path, init.qualname, True)
        for b in info.bases:
            out += self._subclass_deps(self.ix.resolve(t.path, "", b), line, depth + 1)
        return out

    def class_view_deps(self, handler: Target, depth: int = 0) -> list[DepUse]:
        """Class-based views (fastapi-utils ``cbv``, mealie ``@controller``): class attributes
        ``user: User = Depends(get_current_user)`` are dependencies of every method endpoint."""
        cls_name = handler.name.rpartition(".")[0]
        cls = Target("class", handler.path, cls_name)
        return self._class_attr_deps(cls, depth) if cls_name else []

    def _class_attr_deps(self, cls: Target, depth: int) -> list[DepUse]:
        info = self.ix.klass(cls)
        if info is None or depth > 5:
            return []
        scope = cls.name.rpartition(".")[0]
        out: list[DepUse] = []
        for b in info.bases:
            out += self._class_attr_deps(self.ix.resolve(cls.path, scope, b), depth + 1)
        for v in info.fields.values():
            if v is not None:
                d = self._dep_from_call(v, cls.path, scope, False)
                if d is not None:
                    out.append(d)
        return out

    def node_of(self, t: Target, depth: int = 0) -> NodeKey | None:
        if depth > 6:
            return None
        if t.kind == "assign":
            key = (t.path, t.scope, t.name)
            if key in self.nodes:
                return key
            a = self.ix.assign(t)
            if a and a.value.kind == "call" and a.value.dotted:  # router = make_router()
                return self._factory_node(self.ix.resolve(t.path, a.scope, a.value.dotted), depth)
            return None
        if t.kind == "instance_attr" and t.name.endswith(".router"):  # app.router.include_router
            return self.node_of(Target("assign", t.path, t.name[: -len(".router")], t.scope))
        if t.kind == "param":  # create_application(router=router): bind to the call sites' args
            for v, path, scope in self._param_args(t):
                bound = self._value_node(v, path, scope, depth + 1)
                if bound:
                    return bound
        return None

    def call_sites(self) -> dict[tuple[str, str], list[tuple[Value, str, str]]]:
        """Calls of local functions from assignments: (callee path, qualname) -> call values."""
        if self._call_sites is None:
            self._call_sites = {}
            for path, s in self.ix.files.items():
                for a in [*s.assigns, *s.call_stmts]:
                    if a.value.kind == "call" and a.value.dotted:
                        t = self.ix.resolve(path, a.scope, a.value.dotted)
                        if t.kind == "function":
                            self._call_sites.setdefault((t.path, t.name), []).append(
                                (a.value, path, a.scope)
                            )
        return self._call_sites

    def _lifespans(self) -> dict[tuple[str, str], NodeKey]:
        if "_lifespan_map" not in self.__dict__:
            out: dict[tuple[str, str], NodeKey] = {}
            for key in self.nodes:
                path, scope, name = key
                a = self.ix.assign(Target("assign", path, name, scope))
                lv = a.value.kwargs.get("lifespan") if a is not None else None
                if lv is not None and lv.dotted:
                    ft = self.ix.resolve(path, scope, lv.dotted)
                    if ft.kind == "function":
                        out[(ft.path, ft.name)] = key
            self.__dict__["_lifespan_map"] = out
        return self.__dict__["_lifespan_map"]  # type: ignore[no-any-return]

    def _param_args(self, t: Target) -> list[tuple[Value, str, str]]:
        fn = self.ix.function(Target("function", t.path, t.scope))
        if fn is None:
            return []
        owner = self._lifespans().get((t.path, t.scope))
        if owner is not None and fn.params and fn.params[0].name == t.name:
            # FastAPI(lifespan=fn): Starlette calls fn(app) with the application itself.
            node = self.nodes[owner]
            return [(Value(kind="name", dotted=owner[2]), node.key[0], owner[1])]
        names = [p.name for p in fn.params]
        idx = names.index(t.name)
        if names and names[0] in ("self", "cls"):
            idx -= 1
        out = []
        for call, path, scope in self.call_sites().get((t.path, t.scope), []):
            v = call.kwargs.get(t.name) or (call.args[idx] if 0 <= idx < len(call.args) else None)
            if v is not None:
                out.append((v, path, scope))
        return out

    def _factory_node(self, t: Target, depth: int) -> NodeKey | None:
        if depth > 8:
            return None
        if t.kind == "instance_attr":  # users.get_auth_router() where users = LocalClass(...)
            t = self._method_of_instance(t) or t
        fn = self.ix.function(t)
        if fn is None:
            return None
        for name in fn.return_names:
            inner = self.ix.resolve(t.path, fn.qualname, name)
            key = self.node_of(inner, depth + 1)
            if key:
                return key
        for callee in fn.return_calls:  # return get_auth_router(...)
            key = self._factory_node(self.ix.resolve(t.path, fn.qualname, callee), depth + 1)
            if key:
                return key
        return None

    def _method_of_instance(self, t: Target) -> Target | None:
        obj, _, attr = t.name.rpartition(".")
        a = self.ix.assign(Target("assign", t.path, obj, t.scope))
        if a is None or a.value.kind != "call" or not a.value.dotted:
            return None
        cls = self.ix.resolve(t.path, a.scope, a.value.dotted)
        meth = Target("function", cls.path, f"{cls.name}.{attr}")
        return meth if cls.kind == "class" and self.ix.function(meth) else None

    def _receiver(self, path: str, scope: str, dotted: str) -> NodeKey | None:
        return self.node_of(self.ix.resolve(path, scope, dotted))

    def _dep_list(
        self, v: Value | None, path: str, scope: str, inherited: bool, depth: int = 0
    ) -> list[DepUse]:
        if v is not None and v.kind == "name" and v.dotted and depth < 4:
            # dependencies=admin_ui_checks, a list defined elsewhere
            a = self.ix.assign(t := self.ix.resolve(path, scope, v.dotted))
            if a is not None:
                return self._dep_list(a.value, t.path, a.scope, inherited, depth + 1)
        out: list[DepUse] = []
        items = [] if v is None else v.items if v.kind == "list" else [v]  # tolerate a bare Depends
        for item in items:
            d = self._dep_from_call(item, path, scope, inherited)
            if d is None and item.kind == "call" and item.dotted:
                # dependencies=[require_permissions("x")] where the factory returns Depends(fn)
                fn = self.ix.function(self.ix.resolve(path, scope, item.dotted))
                if fn is not None and any(c.split(".")[-1] in DEP_CALLS for c in fn.return_calls):
                    d = DepUse(item, path, scope, self._loc(path, item.line), inherited)
            if d:
                out.append(d)
        return out

    def _dep_from_call(
        self, v: Value, path: str, scope: str, inherited: bool, annotation: Value | None = None
    ) -> DepUse | None:
        if v.kind != "call" or not v.dotted or v.dotted.split(".")[-1] not in DEP_CALLS:
            return None
        target = v.args[0] if v.args else v.kwargs.get("dependency") or annotation
        if target is None:
            return None
        return DepUse(target, path, scope, self._loc(path, v.line), inherited)

    def param_deps(self, fn: Function, path: str) -> list[tuple[str, DepUse]]:
        """(param name, dependency) for ``Depends`` defaults and ``Annotated[..., Depends()]``."""
        out: list[tuple[str, DepUse]] = []
        # Defaults and annotations are evaluated where the function is defined, not inside it:
        # `api_key: str = Security(api_key)` refers to the module-level scheme, not the param.
        outer = fn.qualname.split("#")[0].rpartition(".")[0]
        for p in fn.params:
            if p.default is not None:
                d = self._dep_from_call(p.default, path, outer, False, p.annotation)
                if d:
                    out.append((p.name, d))
                    continue
            for d in self._annotated_deps(p.annotation, path, outer, 0):
                out.append((p.name, d))
        return out

    def _annotated_deps(self, ann: Value | None, path: str, scope: str, depth: int) -> list[DepUse]:
        if ann is None or depth > 4:
            return []
        if ann.kind == "subscript" and (ann.dotted or "").split(".")[-1] == "Annotated":
            base = ann.items[0] if ann.items else None
            return [
                d
                for meta in ann.items[1:]
                if (d := self._dep_from_call(meta, path, scope, False, base)) is not None
            ]
        if ann.kind == "name" and ann.dotted:  # type alias: CurrentUser = Annotated[...]
            t = self.ix.resolve(path, scope, ann.dotted)
            a = self.ix.assign(t)
            if a is not None:
                return self._annotated_deps(a.value, t.path, a.scope, depth + 1)
        return []

    def _attach(self) -> None:
        for path, s in self.ix.files.items():
            for fn in s.functions.values():
                scope = fn.qualname.rpartition(".")[0]
                for dec in fn.decorators:
                    if dec.kind != "call" or not dec.dotted or "." not in dec.dotted:
                        continue
                    recv, _, meth = dec.dotted.rpartition(".")
                    if meth not in HTTP_METHODS and meth != "api_route":
                        continue
                    key = self._receiver(path, scope, recv)
                    if key is None:
                        continue
                    methods = [meth.upper()]
                    if meth == "api_route":
                        mv = dec.kwargs.get("methods")
                        methods = (
                            [str(i.const).upper() for i in mv.items if i.kind == "const"]
                            if mv and mv.kind == "list"
                            else ["GET"]
                        )
                    pv = dec.args[0] if dec.args else dec.kwargs.get("path")
                    self.nodes[key].routes.append(
                        RouteDecl(
                            methods=methods,
                            path=self.ix.eval_str(path, scope, pv) if pv else "",
                            handler=Target("function", path, fn.qualname),
                            deps=self._dep_list(dec.kwargs.get("dependencies"), path, scope, False),
                            loc=self._loc(path, fn.line),
                            file=path,
                            scope=scope,
                        )
                    )
            for mc in s.method_calls:
                key = self._receiver(path, mc.scope, mc.receiver)
                if key is None:
                    continue
                node = self.nodes[key]
                loc = self._loc(path, mc.line)
                if mc.method == "include_router":
                    cv = mc.args[0] if mc.args else mc.kwargs.get("router")
                    child = self._value_node(cv, path, mc.scope)
                    if child:
                        pv = mc.kwargs.get("prefix")
                        node.includes.append(
                            Include(
                                child=child,
                                prefix=self.ix.eval_str(path, mc.scope, pv) if pv else "",
                                deps=self._dep_list(
                                    mc.kwargs.get("dependencies"), path, mc.scope, True
                                ),
                                loc=loc,
                            )
                        )
                elif mc.method == "mount":
                    pv = mc.args[0] if mc.args else mc.kwargs.get("path")
                    av = mc.args[1] if len(mc.args) > 1 else mc.kwargs.get("app")
                    child = self._value_node(av, path, mc.scope)
                    if child:
                        node.mounts.append(
                            Mount(child, self.ix.eval_str(path, mc.scope, pv) if pv else "", loc)
                        )
                elif mc.method == "add_api_route":
                    pv = mc.args[0] if mc.args else mc.kwargs.get("path")
                    ev = mc.args[1] if len(mc.args) > 1 else mc.kwargs.get("endpoint")
                    if ev is None or ev.dotted is None:
                        continue
                    handler = self.ix.resolve(path, mc.scope, ev.dotted)
                    if handler.kind != "function":
                        continue
                    mv = mc.kwargs.get("methods")
                    methods = (
                        [str(i.const).upper() for i in mv.items if i.kind == "const"]
                        if mv and mv.kind == "list"
                        else ["GET"]
                    )
                    node.routes.append(
                        RouteDecl(
                            methods=methods,
                            path=self.ix.eval_str(path, mc.scope, pv) if pv else "",
                            handler=handler,
                            deps=self._dep_list(
                                mc.kwargs.get("dependencies"), path, mc.scope, False
                            ),
                            loc=loc,
                            file=path,
                            scope=mc.scope,
                        )
                    )

    def _value_node(self, v: Value | None, path: str, scope: str, depth: int = 0) -> NodeKey | None:
        if v is None or depth > 6:
            return None
        if v.kind == "name" and v.dotted:
            return self.node_of(self.ix.resolve(path, scope, v.dotted), depth)
        if v.kind == "call" and v.dotted:  # include_router(make_router())
            return self._factory_node(self.ix.resolve(path, scope, v.dotted), depth)
        return None

    # --- dependency closure ----------------------------------------------------------------

    def closure(self, dep: DepUse, depth: int = 0) -> Closure:
        key = (dep.path, dep.scope, repr(dep.value.model_dump(exclude={"line"})))
        if key in self._closure_cache:
            return self._closure_cache[key]
        self._closure_cache[key] = Closure()  # cycle guard
        out = self._closure(dep, depth)
        self._closure_cache[key] = out
        return out

    def _guard(
        self,
        symbol: str,
        info_kind: GuardKind,
        conf: float,
        source: GuardSource,
        on_fail: OnFail,
        cond: str | None,
        loc: Loc | None,
    ) -> GuardRef:
        decl = self.config.guard_decl(symbol)
        if decl is not None:
            return GuardRef(
                symbol=symbol,
                kind=decl.kind,
                source="config",
                confidence=1.0,
                on_fail="raise",
                condition=cond,
                loc=loc,
            )
        return GuardRef(
            symbol=symbol,
            kind=info_kind,
            source=source,
            confidence=conf,
            on_fail=on_fail,
            condition=cond,
            loc=loc,
        )

    def _enriched(self, t: Target) -> Function | None:
        """The function with raise statuses resolved across modules
        (``raise privileges_exception`` where it is ``HTTPException(403)`` elsewhere)."""
        fn = self.ix.function(t)
        if fn is None or all(r.status is not None or not r.exc for r in fn.raises):
            return fn
        raises = []
        for r in fn.raises:
            if r.status is None and r.exc and r.exc != "<reraise>":
                et = self.ix.resolve(t.path, fn.qualname, r.exc)
                a = self.ix.assign(et)
                if a is not None and a.value.kind == "call":
                    sv = a.value.kwargs.get("status_code") or (
                        a.value.args[0] if a.value.args else None
                    )
                    if sv is not None and sv.kind == "const" and isinstance(sv.const, int):
                        r = r.model_copy(update={"status": sv.const})
                    elif sv is not None and sv.dotted:
                        m = re.search(r"HTTP_(\d{3})", sv.dotted)
                        r = r.model_copy(update={"status": int(m.group(1))}) if m else r
            raises.append(r)
        return fn.model_copy(update={"raises": raises})

    def _helpers(self, path: str, scope: str, callee: str) -> list[Function]:
        """Functions a guard delegates to: a helper function, or every method of a checker class
        it instantiates or calls (``check = KeyChecker(...); await check(request)``)."""
        t = self.ix.resolve(path, scope, callee)
        if t.kind == "function":
            fn = self.ix.function(t)
            return [fn] if fn is not None else []
        if t.kind == "assign":
            a = self.ix.assign(t)
            if a is not None and a.value.kind == "call" and a.value.dotted:
                t = self.ix.resolve(t.path, a.scope, a.value.dotted)
        return self._class_methods(t, 0) if t.kind == "class" else []

    def _class_methods(self, t: Target, depth: int) -> list[Function]:
        info = self.ix.klass(t)
        if info is None or depth > 4:
            return []
        out = [f for q in info.methods if (f := self.ix.function(Target("function", t.path, q)))]
        for b in info.bases:
            out += self._class_methods(self.ix.resolve(t.path, "", b), depth + 1)
        return out

    def _function_closure(self, t: Target, depth: int) -> Closure:
        fn = self._enriched(t)
        out = Closure()
        if fn is None:
            return out
        symbol = self.ix.qualified(t)
        uses_scheme = after_authn = False
        for _, d in self.param_deps(fn, t.path):
            sub = self.closure(d, depth + 1)
            out.guards += sub.guards
            out.unresolved += sub.unresolved
            if any(g.source == "builtin" for g in sub.guards):
                uses_scheme = True
            if any(
                g.kind == GuardKind.AUTHN and g.source != "builtin" and self._enforcing(g)
                for g in sub.guards
            ):
                after_authn = True
        helpers = [
            h for c in fn.calls for h in self._helpers(t.path, fn.qualname, c) if h is not fn
        ]
        info = classify(fn, helpers, uses_scheme and not after_authn, after_authn)
        decl = self.config.guard_decl(symbol)
        if info is not None or decl is not None:
            out.guards.insert(
                0,
                self._guard(
                    symbol,
                    info.kind if info else GuardKind.AUTHN,
                    info.confidence if info else 1.0,
                    "scored",
                    info.on_fail if info else "raise",
                    info.condition if info else None,
                    self._loc(t.path, fn.line),
                ),
            )
        return out

    def _closure(self, dep: DepUse, depth: int) -> Closure:
        if depth > MAX_DEP_DEPTH:
            return Closure(unresolved=["<depth limit>"])
        v = dep.value
        if v.kind == "call" and v.dotted:  # Depends(current_user(active=True)) / Depends(Cls(..))
            callee = self.ix.resolve(dep.path, dep.scope, v.dotted)
            return self._target_closure(callee, v, depth)
        if v.kind == "name" and v.dotted:
            return self._target_closure(self.ix.resolve(dep.path, dep.scope, v.dotted), None, depth)
        if v.kind == "subscript" and v.dotted:  # Depends() on a generic class annotation
            return self._target_closure(self.ix.resolve(dep.path, dep.scope, v.dotted), None, depth)
        return Closure(unresolved=["<expression>"])

    def _factory_closure(self, t: Target, fn: Function, call: Value, depth: int) -> Closure | None:
        """Dependency factories: ``def require_role(r): def checker(...): ...; return checker``
        and flag-selected returns: ``get_user(required=False)`` -> ``_get_user_optional``."""
        env: dict[str, bool] = {}
        params = [p for p in fn.params if p.name not in ("self", "cls")]
        for i, p in enumerate(params):
            v = call.kwargs.get(p.name) or (call.args[i] if i < len(call.args) else p.default)
            if v is not None and v.kind == "const" and isinstance(v.const, bool):
                env[p.name] = v.const
        closures: list[Closure] = []
        for name in dict.fromkeys(fn.return_names):
            if evaluate(fn.return_conds.get(name), env) is False:
                continue  # branch not taken for these arguments
            inner = self.ix.resolve(t.path, fn.qualname, name)
            if inner.kind == "function":
                closures.append(self._function_closure(inner, depth))
        if not closures:
            return None
        outer = self._function_closure(t, depth)
        enforcing = [any(self._enforcing(g) for g in c.guards) for c in closures]
        if len(set(enforcing)) > 1:  # depends on a runtime value we could not fold
            return Closure(unresolved=[f"{fn.qualname}(<conditional>)"])
        first = closures[0]
        return Closure(first.guards + outer.guards, first.unresolved + outer.unresolved)

    def _target_closure(self, t: Target, call: Value | None, depth: int) -> Closure:
        if t.kind == "external":
            info = builtin_external(t.name, call)
            if info is not None:
                return Closure(
                    guards=[
                        self._guard(
                            t.name, info.kind, info.confidence, "builtin", info.on_fail, None, None
                        )
                    ]
                )
            decl = self.config.guard_decl(t.name)
            if decl is not None:
                return Closure(
                    guards=[self._guard(t.name, decl.kind, 1.0, "config", "raise", None, None)]
                )
            if t.name.rsplit(".", 1)[-1] in NON_GUARD_EXTERNAL:
                return Closure()
            return Closure(unresolved=[t.name] if AUTHISH_EXTERNAL.search(t.name) else [])
        if t.kind == "function":
            fn = self.ix.function(t)
            if call is not None and fn is not None and fn.return_depends:
                # def require(perm): return Depends(RequirePermission(perm))
                out = Closure()
                for v in fn.return_depends:
                    c = self.closure(
                        DepUse(v, t.path, fn.qualname, self._loc(t.path, fn.line)), depth + 1
                    )
                    out.guards += c.guards
                    out.unresolved += c.unresolved
                return out
            if call is not None and fn is not None and fn.return_names:
                factory = self._factory_closure(t, fn, call, depth)
                if factory is not None:
                    return factory
            return self._function_closure(t, depth)
        if t.kind == "class":
            cinfo = self.ix.klass(t)
            init = Target("function", t.path, f"{t.name}.__init__")
            call_m = Target("function", t.path, f"{t.name}.__call__")
            if call is not None and self.ix.function(call_m):  # Depends(RoleChecker([...]))
                return self._function_closure(call_m, depth)
            if self.ix.function(init):
                return self._function_closure(init, depth)
            if cinfo is not None:  # dataclass / pydantic model dependency: no guard
                for b in cinfo.bases:
                    bt = self.ix.resolve(t.path, "", b)
                    if bt.kind == "external" and builtin_external(bt.name, call):
                        return self._target_closure(bt, call, depth)
            return Closure()
        if t.kind == "assign":
            a = self.ix.assign(t)
            if a is not None and a.value.kind == "call" and a.value.dotted:
                callee = self.ix.resolve(t.path, a.scope, a.value.dotted)
                if callee.kind == "external":
                    return self._target_closure(callee, a.value, depth)
                if callee.kind == "class":
                    call_m = Target("function", callee.path, f"{callee.name}.__call__")
                    if self.ix.function(call_m):
                        return self._function_closure(call_m, depth)
                    cls_info = self.ix.klass(callee)
                    for b in cls_info.bases if cls_info else []:
                        bt = self.ix.resolve(callee.path, "", b)
                        if bt.kind == "external":
                            return self._target_closure(bt, a.value, depth)
                    return Closure()
                if callee.kind in ("function", "instance_attr"):
                    return self._target_closure(callee, a.value, depth)
                info = builtin_external(a.value.dotted, a.value)  # param.current_user(...)
                if info is not None:
                    return Closure(
                        guards=[
                            self._guard(
                                a.value.dotted,
                                info.kind,
                                info.confidence,
                                "builtin",
                                info.on_fail,
                                None,
                                None,
                            )
                        ]
                    )
            names = [t.name] + ([a.value.dotted] if a is not None and a.value.dotted else [])
            # An alias of something we cannot resolve (e.g. an attribute of a parameter).
            return Closure(unresolved=[n for n in names if AUTHISH_EXTERNAL.search(n)][:1])
        if t.kind == "instance_attr":
            # fastapi_users.current_user(...) where fastapi_users = FastAPIUsers(...)
            obj, _, attr = t.name.rpartition(".")
            base = self.ix.assign(Target("assign", t.path, obj, t.scope))
            if base is not None and base.value.dotted:
                cls = self.ix.resolve(t.path, base.scope, base.value.dotted)
                if cls.kind == "external":
                    return self._target_closure(
                        Target("external", "", f"{cls.name}.{attr}"), call, depth
                    )
                meth = Target("function", cls.path, f"{cls.name}.{attr}")
                if self.ix.function(meth):
                    return self._target_closure(meth, call, depth)
            info = builtin_external(t.name, call)  # authenticator.current_user(active=True)
            if info is not None:
                return Closure(
                    guards=[
                        self._guard(
                            t.name, info.kind, info.confidence, "builtin", info.on_fail, None, None
                        )
                    ]
                )
            return Closure(unresolved=[t.name] if AUTHISH_EXTERNAL.search(t.name) else [])
        return Closure(unresolved=[t.name] if AUTHISH_EXTERNAL.search(t.name) else [])

    # --- enumeration -----------------------------------------------------------------------

    def roots(self) -> list[Node]:
        children = {i.child for n in self.nodes.values() for i in n.includes}
        children |= {m.child for n in self.nodes.values() for m in n.mounts}
        apps = [n for n in self.nodes.values() if n.kind == "app" and n.key not in children]
        if apps:
            return sorted(apps, key=lambda n: n.key)
        return sorted(
            (n for n in self.nodes.values() if n.key not in children), key=lambda n: n.key
        )

    def endpoints(self) -> list[Endpoint]:
        out: list[Endpoint] = []
        seen: set[str] = set()
        for root in self.roots():
            self._walk(root, "", list(root.deps), [], out, seen, False, 0)
        return out

    def _walk(
        self,
        node: Node,
        prefix: str,
        deps: list[DepUse],
        chain: list[Loc],
        out: list[Endpoint],
        seen: set[str],
        mounted_under_auth: bool,
        depth: int,
    ) -> None:
        if depth > 32:
            return
        here = _join(prefix, node.prefix) if (prefix or node.prefix != "") else ""
        for r in node.routes:
            for m in r.methods:
                ep = self._endpoint(
                    r, m, _join(here, r.path), deps, chain, node, mounted_under_auth
                )
                if ep is not None and ep.id not in seen:
                    seen.add(ep.id)
                    out.append(ep)
        for inc in node.includes:
            child = self.nodes.get(inc.child)
            if child is not None:
                self._walk(
                    child,
                    _join(here, inc.prefix) if (here or inc.prefix != "") else "",
                    [*deps, *child.deps, *inc.deps],
                    [*chain, inc.loc],
                    out,
                    seen,
                    mounted_under_auth,
                    depth + 1,
                )
        for mnt in node.mounts:
            child = self.nodes.get(mnt.child)
            if child is None:
                continue
            parent_auth = any(self._enforcing(g) for d in deps for g in self.closure(d).guards)
            # Mounted sub-apps do NOT inherit the parent's dependencies (PLAN.md §6.4).
            self._walk(
                child,
                _join(here, mnt.path),
                list(child.deps),
                [*chain, mnt.loc],
                out,
                seen,
                mounted_under_auth or parent_auth,
                depth + 1,
            )

    @staticmethod
    def _enforcing(g: GuardRef) -> bool:
        return g.kind in ENFORCING_KINDS and g.confidence >= CONFIRMED

    def _endpoint(
        self,
        r: RouteDecl,
        method: str,
        path: str,
        inherited: list[DepUse],
        chain: list[Loc],
        node: Node,
        mounted_under_auth: bool,
    ) -> Endpoint | None:
        fn = self._enriched(r.handler)
        if fn is None:
            return None
        guards: list[GuardRef] = []
        unresolved: list[str] = []
        principals: set[str] = set()
        for d in [*inherited, *r.deps]:
            c = self.closure(d)
            for g in c.guards:
                guards.append(
                    g.model_copy(
                        update={
                            "inherited_from": d.loc if d.inherited else None,
                            "dominates_sink": True,
                        }
                    )
                )
            unresolved += c.unresolved
        for d in self.class_view_deps(r.handler):
            c = self.closure(d)
            guards += [g.model_copy(update={"dominates_sink": True}) for g in c.guards]
            unresolved += c.unresolved
        for pname, d in self.param_deps(fn, r.file):
            c = self.closure(d)
            guards += [g.model_copy(update={"dominates_sink": True}) for g in c.guards]
            unresolved += c.unresolved
            if any(
                g.kind in ENFORCING_KINDS or g.kind == GuardKind.OPTIONAL_AUTHN for g in c.guards
            ) or PRINCIPAL_NAME.search(pname):
                principals.add(pname)
        # Inline checks in the handler body count as guards too.
        # Handlers translate service errors in except blocks (``except PermissionError: raise
        # 403``); those are not checks the handler performs, so they don't make a guard.
        inline = fn.model_copy(update={"raises": [r for r in fn.raises if not r.in_except]})
        info = classify(inline, [], False)
        # Reading the object and then checking it is the normal ownership pattern; only a
        # write/delete that happens before the check is a bypass (``sink_before_check``).
        first_write = min((s.line for s in fn.sinks if s.kind != "read"), default=None)
        first_check = min((r.line for r in auth_raises(inline)), default=None)
        if info is not None and info.kind in ENFORCING_KINDS:
            dominates = first_check is None or first_write is None or first_check < first_write
            guards.append(
                GuardRef(
                    symbol=self.ix.qualified(r.handler),
                    kind=info.kind,
                    source="scored",
                    confidence=info.confidence,
                    on_fail=info.on_fail,
                    condition=info.condition,
                    dominates_sink=dominates,
                    loc=self._loc(r.file, fn.line),
                )
            )
        guards = _dedupe(guards)
        verdict = Verdict.NO_AUTH
        if any(self._enforcing(g) for g in guards):
            verdict = Verdict.AUTH
        elif unresolved or "<dynamic>" in path:
            verdict = Verdict.UNKNOWN
        path_params = set(re.findall(r"{(\w+)(?::\w+)?}", path))
        sinks = [
            Sink(
                kind=s.kind,
                orm=s.orm,
                model=s.model,
                id_param=next((n for n in s.predicate_names if n in path_params), None),
                principal_scoped=bool(principals & set(s.predicate_names)),
                loc=self._loc(r.file, s.line),
            )
            for s in fn.sinks
        ]
        has_role = any(g.kind == GuardKind.AUTHZ_ROLE and self._enforcing(g) for g in guards)
        mass = [] if has_role else self._mass_assigned(fn, r.file)
        ep_id = f"{method} {path}"
        sensitivity = set()
        if method == "DELETE":
            sensitivity.add("delete")
        if method in {"POST", "PUT", "PATCH", "DELETE"}:
            sensitivity.add("write")
        if "admin" in path.lower():
            sensitivity.add("admin_path")
        if mass:
            sensitivity.add("role_write")
        public = self.config.is_public(ep_id) is not None
        return Endpoint(
            id=ep_id,
            method=method,
            path=path,
            framework="fastapi",
            handler=self.ix.qualified(r.handler),
            loc=r.loc,
            guards=guards,
            authn=verdict,
            sensitivity=sensitivity,
            sinks=sinks,
            public_by_config=public,
            mounted_under_auth=mounted_under_auth,
            chain=chain,
            unresolved=sorted(set(unresolved)),
            mass_assign_fields=mass,
            router_group=f"{node.key[0]}:{node.key[2]}",
        )

    def _mass_assigned(self, fn: Function, path: str) -> list[str]:
        fields: set[str] = set()
        for ma in fn.mass_assign:
            p = next((p for p in fn.params if p.name == ma.source), None)
            if p is None or p.annotation is None or p.annotation.dotted is None:
                continue
            cls = self.ix.resolve(path, fn.qualname, p.annotation.dotted)
            names = set(self.ix.class_fields(cls)) - set(ma.excluded)
            fields |= names & PRIVILEGED_FIELDS
        return sorted(fields)


def _dedupe(guards: list[GuardRef]) -> list[GuardRef]:
    seen: set[tuple[str, str]] = set()
    out = []
    for g in guards:
        k = (g.symbol, g.kind)
        if k not in seen:
            seen.add(k)
            out.append(g)
    return out
