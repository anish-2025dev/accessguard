"""Express route graph, mount tree and middleware order (FR-3.1, FR-3.2 Express; PLAN.md §6.4).

The summaries' source-ordered events are replayed by a small abstract interpreter: values are
apps/routers, functions, imported packages, literals and "unknown". Calls on an app or router
record ``use``/``get``/``route`` entries with a global sequence number, which is the order in
which Express itself would register them. Nothing from the scanned repository is executed.

Guard chain (PLAN.md §6.4): middleware M guards route R when M is registered on R's router or an
ancestor, before R (before the mount point, in an ancestor), its path matches (prefix match for
``use``, exact for routes), and its method matches; plus R's own handlers before the last one.
Middleware that matches but is registered after R is recorded as a *late guard* (AG-AUTH-002
``guard_reordered``, AG-AUTH-003). ``mw.unless({path})`` exempts the listed paths.
"""

from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass, field
from typing import Union

from authgraph.facts.models import (
    ENFORCING_KINDS,
    Endpoint,
    GuardRef,
    Loc,
    Verdict,
)
from authgraph.guards.config import Config
from authgraph.guards.js_scoring import classify_function, known_external
from authgraph.guards.scoring import AUTHISH_EXTERNAL, CONFIRMED, GuardInfo
from authgraph.lang.js.resolver import NodeResolver
from authgraph.lang.js.summary import JsFileSummary, JsFunction, JsImport, JsValue

HTTP_METHODS = frozenset({"get", "post", "put", "patch", "delete", "options", "head", "all"})
NON_GUARD_PACKAGES = frozenset(
    {
        "express",
        "cors",
        "helmet",
        "morgan",
        "compression",
        "cookie-parser",
        "body-parser",
        "express-rate-limit",
        "multer",
        "celebrate",
        "express-validator",
        "csurf",
        "serve-favicon",
        "serve-index",
        "method-override",
        "express-session",
        "connect-timeout",
        "response-time",
        "express-fileupload",
        "swagger-ui-express",
        "hpp",
        "xss-clean",
        "express-mongo-sanitize",
        "express-winston",
    }
)
# finale-rest (and its predecessor epilogue) generate CRUD routes from Sequelize models.
FINALE_INIT = frozenset({"finale-rest.initialize", "epilogue.initialize"})
FINALE_RESOURCE = frozenset({"finale-rest.resource", "epilogue.resource"})
MAX_CALL_DEPTH = 12
MAX_STEPS = 200_000
DYNAMIC = "<dynamic>"


# ---- abstract values ---------------------------------------------------------------------------
@dataclass(eq=False)
class Entry:
    seq: int
    kind: str  # "use" | "route"
    methods: list[str]  # upper-case; "ALL" for use / app.all
    paths: list[str | None]  # None: not a constant
    handlers: list[V]
    loc: Loc


@dataclass(eq=False)
class Node:
    kind: str  # "app" | "router"
    key: str
    loc: Loc
    entries: list[Entry] = field(default_factory=list)
    mounted: bool = False


@dataclass(eq=False)
class Fn:
    file: str
    fid: str
    env: Env | None
    origin: str = ""


@dataclass(eq=False)
class Ext:
    name: str  # "<package>.<export path>"
    called: bool = False
    args: list[V] = field(default_factory=list)
    origin: str = ""


@dataclass(eq=False)
class Mod:
    path: str


@dataclass(eq=False)
class Obj:
    props: dict[str, V] = field(default_factory=dict)


@dataclass(eq=False)
class Arr:
    items: list[V] = field(default_factory=list)


@dataclass(eq=False)
class Lit:
    kind: str  # "str" | "regex" | "num" | "bool" | "null"
    s: str = ""


@dataclass(eq=False)
class Chain:
    node: Node
    paths: list[str | None]


@dataclass(eq=False)
class Bound:
    target: Node | Chain | Arr | V
    method: str


@dataclass(eq=False)
class Unless:
    inner: V
    exempt: list[str | re.Pattern[str] | None]


@dataclass(eq=False)
class Unk:
    name: str = ""
    origin: str = ""


V = Union[Node, Fn, Ext, Mod, Obj, Arr, Lit, Chain, Bound, Unless, Unk]  # noqa: UP007


@dataclass(eq=False)
class Env:
    vars: dict[str, V]
    parent: Env | None
    file: str


@dataclass
class _Mw:
    """A middleware occurrence, with the absolute paths it applies to."""

    value: V
    paths: list[str | None]
    exact: bool  # route registration (exact path) vs use (prefix)
    methods: list[str]
    seq: int
    loc: Loc


@dataclass
class _Class:
    kind: str  # "guard" | "passthrough" | "terminal" | "unknown_auth" | "unknown" | "node"
    symbol: str
    info: GuardInfo | None = None
    exempt: list[str | re.Pattern[str] | None] = field(default_factory=list)


class ExpressGraph:
    def __init__(
        self, files: dict[str, JsFileSummary], resolver: NodeResolver, config: Config
    ) -> None:
        self.files = files
        self.rs = resolver
        self.config = config
        self.seq = 0
        self.steps = 0
        self.nodes: list[Node] = []
        self.module_env: dict[str, Env] = {}
        self.module_exports: dict[str, dict[str, V]] = {}
        self.executing: set[str] = set()
        self.stack: list[str] = []
        self.invoked_callbacks: set[str] = set()
        self.fn_index: dict[str, tuple[str, JsFunction]] = {
            fid: (p, f) for p, s in files.items() for fid, f in s.functions.items()
        }
        self._class_cache: dict[int, _Class] = {}
        self.finale_app: Node | None = None

    # ---- module execution ------------------------------------------------------------------
    def run(self) -> None:
        for path in sorted(self.files):
            self.module(path)

    def module(self, path: str) -> Env:
        env = self.module_env.get(path)
        if env is not None:
            return env
        env = Env({}, None, path)
        self.module_env[path] = env
        self.module_exports[path] = {}
        s = self.files[path]
        mod = s.functions.get(s.module_fn)
        if mod is not None and not s.parse_error:
            self.executing.add(path)
            self.exec_events(mod, env)
            self.executing.discard(path)
        return env

    def export(self, path: str, name: str) -> V:
        env = self.module(path)
        s = self.files[path]
        runtime = self.module_exports.get(path, {})
        if name == "*":
            if "default" in runtime and not s.exports.keys() - {"default"} - set(runtime):
                return runtime["default"]  # CommonJS module.exports = x
            return Mod(path)
        if name in runtime:
            return runtime[name]
        if name in s.exports:
            return self.eval(s.exports[name], env)
        default = runtime.get("default")
        if isinstance(default, Obj) and name in default.props:
            return default.props[name]
        for re_ in s.reexports:
            target = self.rs.resolve(path, re_.source)
            if target is not None and target != path:
                v = self.export(target, name)
                if not (isinstance(v, Unk) and not v.name):
                    return v
        return Unk(f"{path}:{name}")

    def import_value(self, file: str, imp: JsImport) -> V:
        target = self.rs.resolve(file, imp.source)
        if target is not None:
            return self.export(target, imp.name)
        if self.rs.is_local_alias(file, imp.source):
            return Unk(f"{imp.source}:{imp.name}")
        pkg = imp.source
        if imp.name in {"*", "default"}:
            return Ext(pkg)
        return Ext(f"{pkg}.{imp.name}")

    # ---- interpretation ----------------------------------------------------------------------
    def exec_events(self, fn: JsFunction, env: Env) -> None:
        for ev in fn.events:
            self.steps += 1
            if self.steps > MAX_STEPS:
                return
            if ev.k == "assign":
                if ev.name in {"module.exports", "exports"}:
                    v = self.eval(ev.value, env)
                    exp = self.module_exports.setdefault(env.file, {})
                    exp["default"] = v
                    if isinstance(v, Obj):
                        for k, pv in v.props.items():
                            exp.setdefault(k, pv)
                elif ev.name.startswith(("module.exports.", "exports.")):
                    v = self.eval(ev.value, env)
                    exp = self.module_exports.setdefault(env.file, {})
                    key = ev.name.rsplit(".", 1)[-1]
                    exp[key] = v
                    d = exp.get("default")
                    if isinstance(d, Obj):
                        d.props[key] = v
                    elif d is None:
                        exp["default"] = Obj({key: v})
                elif "." in ev.name:
                    head, _, attr = ev.name.rpartition(".")
                    obj = self.lookup(head, env) if "." not in head else self.eval_dotted(head, env)
                    if isinstance(obj, Obj):
                        obj.props[attr] = self.eval(ev.value, env)
                else:
                    env.vars[ev.name] = self.eval(ev.value, env)
            else:
                self.eval(ev.value, env)

    def eval_dotted(self, dotted: str, env: Env) -> V:
        parts = dotted.split(".")
        v = self.lookup(parts[0], env)
        for p in parts[1:]:
            v = self.attr(v, p)
        return v

    def lookup(self, name: str, env: Env) -> V:
        e: Env | None = env
        while e is not None:
            if name in e.vars:
                return e.vars[name]
            e = e.parent
        mod = self.module_env.get(env.file)
        if mod is not None and name in mod.vars:
            return mod.vars[name]
        s = self.files.get(env.file)
        if s is not None and name in s.imports:
            v = self.import_value(env.file, s.imports[name])
            if mod is not None:
                mod.vars[name] = v
            return v
        if name == "require":
            return Ext("#require")
        return Unk(name)

    def eval(self, v: JsValue, env: Env) -> V:
        k = v.k
        if k == "str":
            return Lit("str", v.s)
        if k == "regex":
            return Lit("regex", v.s)
        if k in {"num", "bool", "null"}:
            return Lit(k, v.s)
        if k == "id":
            return self.lookup(v.s, env)
        if k == "member" and v.obj is not None:
            return self.attr(self.eval(v.obj, env), v.s)
        if k in {"call", "new"} and v.obj is not None:
            callee = self.eval(v.obj, env)
            args: list[V] = []
            for a in v.args:
                av = (
                    self.eval(a.obj, env)
                    if a.k == "spread" and a.obj is not None
                    else self.eval(a, env)
                )
                if a.k == "spread" and isinstance(av, Arr):
                    args += av.items
                else:
                    args.append(av)
            return self.call(callee, args, v, env)
        if k == "func":
            return Fn(env.file, v.s, env)
        if k == "tmpl":
            text = ""
            for part in v.args:
                pv = self.eval(part, env)
                if not (isinstance(pv, Lit) and pv.kind in {"str", "num"}):
                    return Unk("")
                text += pv.s
            return Lit("str", text)
        if k == "array":
            items: list[V] = []
            for a in v.args:
                av = (
                    self.eval(a.obj, env)
                    if a.k == "spread" and a.obj is not None
                    else self.eval(a, env)
                )
                if a.k == "spread" and isinstance(av, Arr):
                    items += av.items
                else:
                    items.append(av)
            return Arr(items)
        if k == "object":
            return Obj({key: self.eval(pv, env) for key, pv in v.props.items()})
        return Unk("")

    def attr(self, obj: V, name: str) -> V:
        if isinstance(obj, (Node, Chain)):
            return Bound(obj, name)
        if isinstance(obj, Arr) and name in {"forEach", "map"}:
            return Bound(obj, name)
        if name == "unless" and isinstance(obj, (Ext, Fn, Unk)):
            return Bound(obj, "unless")  # express-unless: mw.unless({path: [...]})
        if isinstance(obj, Mod):
            return self.export(obj.path, name)
        if isinstance(obj, Obj):
            return obj.props.get(name, Unk(name))
        if isinstance(obj, Ext):
            if obj.name == "#require":
                return Unk(name)
            return Ext(f"{obj.name}.{name}" if not obj.called else f"{obj.name}().{name}")
        if isinstance(obj, Unk):
            return Unk(f"{obj.name}.{name}" if obj.name else name)
        return Unk(name)

    def call(self, callee: V, args: list[V], src: JsValue, env: Env) -> V:
        loc = Loc(path=env.file, line=src.line)
        if isinstance(callee, Ext):
            if callee.name == "#require":
                if args and isinstance(args[0], Lit) and args[0].kind == "str":
                    return self.import_value(
                        env.file, JsImport(source=args[0].s, name="*", line=src.line)
                    )
                return Unk("require")
            if callee.name in {"express", "express.default"}:
                return self.new_node("app", loc)
            if callee.name in {"express.Router", "express.default.Router", "router"}:
                return self.new_node("router", loc)
            if callee.name in FINALE_INIT:
                opts = args[0] if args else None
                app = opts.props.get("app") if isinstance(opts, Obj) else None
                self.finale_app = app if isinstance(app, Node) else None
                return Unk("finale")
            if callee.name in FINALE_RESOURCE and self.finale_app is not None and args:
                self.finale_resource(self.finale_app, args[0], callee.name, loc)
                return Unk("resource")
            self.callbacks(args)
            return Ext(callee.name, True, args)
        if isinstance(callee, Bound):
            return self.bound_call(callee, args, loc, env)
        if isinstance(callee, Fn):
            return self.invoke(callee, args)
        # Unknown callee: still follow inline callbacks (promise .then, wrappers).
        self.callbacks(args)
        if isinstance(callee, Unk) and AUTHISH_EXTERNAL.search(callee.name):
            return Unk(callee.name + "()")
        return Unk(callee.name + "()" if isinstance(callee, Unk) and callee.name else "")

    def callbacks(self, args: list[V]) -> None:
        for a in args:
            if isinstance(a, Fn) and a.fid not in self.invoked_callbacks:
                self.invoked_callbacks.add(a.fid)
                fn = self.fn_index.get(a.fid)
                if fn is not None and fn[1].events:
                    self.invoke(a, [])

    def invoke(self, f: Fn, args: list[V]) -> V:
        hit = self.fn_index.get(f.fid)
        if hit is None or len(self.stack) >= MAX_CALL_DEPTH or f.fid in self.stack:
            return Unk("")
        path, fn = hit
        env = Env({}, f.env, path)
        for i, p in enumerate(fn.params):
            arg = args[i] if i < len(args) else Unk(p)
            if p.startswith("{"):
                for pair in filter(None, p[1:-1].split(",")):
                    key, _, local = pair.partition(":")
                    env.vars[local] = (
                        arg.props.get(key, Unk(key)) if isinstance(arg, Obj) else Unk(key)
                    )
            elif p:
                env.vars[p] = arg
        self.stack.append(f.fid)
        try:
            self.exec_events(fn, env)
            out = self.eval(fn.returns[0], env) if fn.returns else Unk("")
        finally:
            self.stack.pop()
        symbol = self.fn_symbol(path, fn)
        if isinstance(out, (Fn, Ext, Unk)) and not out.origin:
            out.origin = symbol
        return out

    def bound_call(self, b: Bound, args: list[V], loc: Loc, env: Env) -> V:
        t, m = b.target, b.method
        if isinstance(t, Arr):
            results = [
                self.call(
                    args[0], [item, Lit("num", str(i))], JsValue(k="other", line=loc.line), env
                )
                if args
                else Unk("")
                for i, item in enumerate(t.items)
            ]
            return Arr(results) if m == "map" else Unk("")
        if m == "unless":
            return Unless(t, self.exemptions(args[0] if args else Unk("")))
        if isinstance(t, Chain):
            if m in HTTP_METHODS:
                self.register(
                    t.node, "route", [m.upper() if m != "all" else "ALL"], t.paths, args, loc
                )
            return t
        if isinstance(t, Node):
            if m in HTTP_METHODS and (m != "get" or len(args) != 1 or not _is_path(args[0])):
                if not args:
                    return t
                paths = _paths(args[0])
                self.register(
                    t, "route", [m.upper() if m != "all" else "ALL"], paths, args[1:], loc
                )
                return t
            if m == "use":
                if args and _is_path(args[0]):
                    self.register(t, "use", ["ALL"], _paths(args[0]), args[1:], loc)
                else:
                    self.register(t, "use", ["ALL"], ["/"], args, loc)
                return t
            if m == "route":
                return Chain(t, _paths(args[0]) if args else [None])
            return t if m in {"set", "enable", "disable", "engine", "param", "locals"} else Unk(m)
        return Unk(m)

    def exemptions(self, opts: V) -> list[str | re.Pattern[str] | None]:
        out: list[str | re.Pattern[str] | None] = []
        paths = opts.props.get("path") if isinstance(opts, Obj) else None
        items = paths.items if isinstance(paths, Arr) else [paths] if paths is not None else [None]
        for it in items:
            if isinstance(it, Obj):
                it = it.props.get("url")
            if isinstance(it, Lit) and it.kind == "str":
                out.append(it.s)
            elif isinstance(it, Lit) and it.kind == "regex":
                try:
                    out.append(re.compile(it.s))
                except re.error:
                    out.append(None)
            else:
                out.append(None)
        return out

    def finale_resource(self, app: Node, opts: V, name: str, loc: Loc) -> None:
        """finale-rest 1.2 ``resource({endpoints: [collection, item]})`` registers, on the app
        given to ``initialize``: list GET + create POST on the collection, read GET + update
        PUT (``updateMethod``) + delete DELETE on the item (lib/Controllers/*.js, base.js:77)."""
        if not isinstance(opts, Obj):
            return
        eps = opts.props.get("endpoints")
        items = eps.items if isinstance(eps, Arr) else []
        paths = [i.s if isinstance(i, Lit) and i.kind == "str" else None for i in items]
        update = opts.props.get("updateMethod")
        upd = update.s.upper() if isinstance(update, Lit) and update.kind == "str" else "PUT"
        handler: list[V] = [Ext(name, True)]
        if paths:
            for m in ("GET", "POST"):
                self.register(app, "route", [m], [paths[0]], handler, loc)
        if len(paths) > 1:
            for m in ("GET", upd, "DELETE"):
                self.register(app, "route", [m], [paths[1]], handler, loc)

    def new_node(self, kind: str, loc: Loc) -> Node:
        n = Node(kind, f"{loc.path}:{loc.line}:{len(self.nodes)}", loc)
        self.nodes.append(n)
        return n

    def register(
        self,
        node: Node,
        kind: str,
        methods: list[str],
        paths: list[str | None],
        handlers: list[V],
        loc: Loc,
    ) -> None:
        flat: list[V] = []
        for h in handlers:
            flat += h.items if isinstance(h, Arr) else [h]
        for h in flat:
            if isinstance(h, Node):
                h.mounted = True
        self.seq += 1
        node.entries.append(Entry(self.seq, kind, methods, paths, flat, loc))

    # ---- classification ------------------------------------------------------------------------
    def fn_symbol(self, path: str, fn: JsFunction) -> str:
        stem = posixpath.splitext(path)[0]
        return f"{stem}.{fn.name or f'<anonymous@{fn.line}>'}"

    def classify(self, v: V) -> _Class:
        cached = self._class_cache.get(id(v))
        if cached is not None:
            return cached
        c = self._classify(v)
        self._class_cache[id(v)] = c
        return c

    def _classify(self, v: V) -> _Class:
        if isinstance(v, Node):
            return _Class("node", v.key)
        if isinstance(v, Unless):
            inner = self.classify(v.inner)
            return _Class(inner.kind, inner.symbol, inner.info, v.exempt)
        if isinstance(v, Ext):
            name = v.name.replace("().", ".")
            opts = _options(v.args) if v.called else {}
            info = known_external(name, opts) or known_external(f"{name}.default", opts)
            symbol = v.origin or name
            if info is not None:
                return _Class("guard", symbol, info)
            pkg = (
                name.split(".", 1)[0]
                if not name.startswith("@")
                else ".".join(name.split(".", 2)[:1])
            )
            if pkg in NON_GUARD_PACKAGES:
                return _Class("passthrough", symbol)
            if AUTHISH_EXTERNAL.search(name.split(".", 1)[-1]) or AUTHISH_EXTERNAL.search(v.origin):
                return _Class("unknown_auth", symbol)
            return _Class("unknown", symbol)
        if isinstance(v, Fn):
            hit = self.fn_index.get(v.fid)
            if hit is None:
                return _Class("unknown", v.origin)
            path, fn = hit
            symbol = v.origin or self.fn_symbol(path, fn)
            if len(fn.params) >= 4:
                return _Class("passthrough", symbol)  # error handler: runs only after a failure
            if not fn.calls_next and (fn.sends or not fn.forwards_next):
                # Never passes the request on (next(err) in a catch is error propagation).
                return _Class("terminal", symbol)
            name = (v.origin.rsplit(".", 1)[-1] + " " if v.origin else "") + (fn.name or "")
            info = classify_function(fn, self.helpers(path, fn, v.env), name)
            if info is not None:
                return _Class("guard", symbol, info)
            if fn.calls_next and not fn.sends:
                return _Class("passthrough", symbol)
            return _Class("terminal", symbol)
        if isinstance(v, Unk):
            name = v.origin or v.name
            if name and AUTHISH_EXTERNAL.search(name):
                return _Class("unknown_auth", name)
            return _Class("unknown", name)
        return _Class("unknown", "")

    def helpers(self, path: str, fn: JsFunction, env: Env | None) -> list[JsFunction]:
        """Local functions the middleware calls (depth 2), e.g. a verify callback."""
        out: list[JsFunction] = []
        seen = {fn.id}
        frontier = [(fn, env)]
        for _ in range(2):
            nxt: list[tuple[JsFunction, Env | None]] = []
            for f, _env in frontier:
                for c in f.calls[:50]:
                    if c.startswith("?."):
                        continue
                    # Module-level names only: a closure parameter is the wrapped handler
                    # (``catchAsync(fn)``), not a helper of the middleware.
                    v = self.eval_dotted(c, self.module(self.fn_index[f.id][0]))
                    if isinstance(v, Fn) and v.fid not in seen:
                        seen.add(v.fid)
                        hit = self.fn_index.get(v.fid)
                        if hit is not None:
                            out.append(hit[1])
                            nxt.append((hit[1], v.env))
            frontier = nxt
        return out

    # ---- endpoints -------------------------------------------------------------------------------
    def endpoints(self) -> list[Endpoint]:
        self.run()
        roots = [n for n in self.nodes if n.kind == "app" and not n.mounted]
        if not roots:  # a library exporting routers: enumerate the unmounted routers
            roots = [n for n in self.nodes if not n.mounted and n.entries]
        terminal: dict[str, Endpoint] = {}
        guard_only: dict[str, Endpoint] = {}
        for root in roots:
            root_loc = Loc(path=root.loc.path, line=root.loc.line)
            for ep in self.walk(root, "", [], [], [root_loc], set()):
                bucket = guard_only if ep.guard_only else terminal
                bucket.setdefault(ep.id, ep)
        out = list(terminal.values()) + [e for k, e in guard_only.items() if k not in terminal]
        return sorted(out, key=lambda e: e.id)

    def walk(
        self,
        node: Node,
        prefix: str,
        inherited: list[_Mw],
        inherited_late: list[_Mw],
        chain: list[Loc],
        seen: set[int],
    ) -> list[Endpoint]:
        if id(node) in seen or len(seen) > 64:
            return []
        seen = seen | {id(node)}
        out: list[Endpoint] = []
        # Pass 1: this node's middleware occurrences (use handlers, route handlers before the
        # last one, and routes made only of middleware), in registration order.
        local: list[_Mw] = []
        only_mw: dict[int, bool] = {}
        for e in node.entries:
            abs_paths = [_join(prefix, p) if p is not None else None for p in e.paths]
            if e.kind == "use":
                local += [
                    _Mw(h, abs_paths, False, e.methods, e.seq, e.loc)
                    for h in e.handlers
                    if not isinstance(h, Node)
                ]
                continue
            if not e.handlers:
                continue
            only = self.classify(e.handlers[-1]).kind in {"guard", "passthrough"}
            only_mw[e.seq] = only
            if only:  # the route passes on: later routes on the same path run after it
                local += [_Mw(h, abs_paths, True, e.methods, e.seq, e.loc) for h in e.handlers]
        # Pass 2: mounts and endpoints.
        for e in node.entries:
            if e.kind == "use":
                before = inherited + [m for m in local if m.seq < e.seq]
                after = inherited_late + [m for m in local if m.seq > e.seq]
                for h in e.handlers:
                    if not isinstance(h, Node):
                        continue
                    for p in e.paths:
                        sub = _join(prefix, p) if p is not None else _join(prefix, DYNAMIC)
                        out += self.walk(h, sub, before, after, [*chain, e.loc], seen)
                continue
            if not e.handlers:
                continue
            for p in e.paths:
                full = _join(prefix, p) if p is not None else _join(prefix, DYNAMIC)
                for m in e.methods:
                    for method in ["GET", "POST", "PUT", "PATCH", "DELETE"] if m == "ALL" else [m]:
                        out.append(
                            self.endpoint(
                                node,
                                e,
                                method,
                                full,
                                inherited,
                                inherited_late,
                                local,
                                chain,
                                only_mw[e.seq],
                            )
                        )
        return out

    def endpoint(
        self,
        node: Node,
        e: Entry,
        method: str,
        path: str,
        inherited: list[_Mw],
        inherited_late: list[_Mw],
        local: list[_Mw],
        chain: list[Loc],
        only_mw: bool,
    ) -> Endpoint:
        guards: list[GuardRef] = []
        late: list[GuardRef] = []
        unresolved: list[str] = []
        dynamic = DYNAMIC in path

        def consider(mw: _Mw, before: bool) -> None:
            applies = _applies(mw, method, path)
            if applies is False:
                return
            c = self.classify(mw.value)
            if c.exempt and _exempt(c.exempt, path):
                return
            if c.kind == "unknown_auth":
                if before:
                    unresolved.append(c.symbol)
                return
            if c.kind != "guard" or c.info is None:
                return
            if applies is None:  # dynamic middleware path: cannot tell
                unresolved.append(c.symbol)
                return
            ref = GuardRef(
                symbol=c.symbol,
                kind=c.info.kind,
                source="builtin" if isinstance(mw.value, Ext) else "scored",
                confidence=c.info.confidence,
                inherited_from=mw.loc if mw.seq != e.seq else None,
                on_fail=c.info.on_fail,
                loc=mw.loc,
            )
            (guards if before else late).append(ref)

        for mw in inherited:
            consider(mw, True)
        for mw in local:
            if mw.seq < e.seq:
                consider(mw, True)
        own = e.handlers if only_mw else e.handlers[:-1]
        for h in own:
            consider(_Mw(h, [path], True, [method], e.seq, e.loc), True)
        for mw in local:
            if mw.seq > e.seq:
                consider(mw, False)
        for mw in inherited_late:
            consider(mw, False)
        guards = _dedupe(guards)
        before_keys = {g.symbol for g in guards}
        late = [
            g
            for g in _dedupe(late)
            if g.symbol not in before_keys
            and g.kind in ENFORCING_KINDS
            and g.confidence >= CONFIRMED
        ]
        enforcing = any(g.kind in ENFORCING_KINDS and g.confidence >= CONFIRMED for g in guards)
        if enforcing:
            verdict = Verdict.AUTH
        elif unresolved or dynamic:
            verdict = Verdict.UNKNOWN
        else:
            verdict = Verdict.NO_AUTH
        last = self.classify(e.handlers[-1])
        if last.kind == "unknown_auth" and not enforcing:
            verdict = Verdict.UNKNOWN
            unresolved.append(last.symbol)
        sensitivity: set[str] = set()
        if method == "DELETE":
            sensitivity.add("delete")
        if method in {"POST", "PUT", "PATCH", "DELETE"}:
            sensitivity.add("write")
        if "admin" in path.lower():
            sensitivity.add("admin_path")
        ep_id = f"{method} {path}"
        return Endpoint(
            id=ep_id,
            method=method,
            path=path,
            framework="express",
            handler=last.symbol or f"{e.loc.path}:{e.loc.line}",
            loc=e.loc,
            guards=guards,
            authn=verdict,
            sensitivity=sensitivity,
            public_by_config=self.config.is_public(ep_id) is not None,
            chain=chain,
            unresolved=sorted(set(unresolved)),
            router_group=node.key,
            late_guards=late,
            guard_only=only_mw,
        )


# ---- helpers ------------------------------------------------------------------------------------
def _is_path(v: V) -> bool:
    if isinstance(v, Lit):
        return v.kind in {"str", "regex"}
    if isinstance(v, Arr):
        return bool(v.items) and all(
            isinstance(i, Lit) and i.kind in {"str", "regex"} for i in v.items
        )
    return False


def _paths(v: V) -> list[str | None]:
    if isinstance(v, Lit) and v.kind == "str":
        return [v.s]
    if isinstance(v, Arr):
        return [i.s if isinstance(i, Lit) and i.kind == "str" else None for i in v.items] or [None]
    return [None]


def _join(prefix: str, p: str) -> str:
    joined = "/" + "/".join(x for x in (prefix + "/" + p).split("/") if x)
    return joined


def _segments(p: str) -> list[str]:
    return [s for s in p.split("/") if s]


def _seg_match(pattern: str, actual: str) -> bool:
    """Does a middleware path segment cover every request to the endpoint's segment?"""
    if pattern.startswith(":") or pattern in {"*", "(.*)"}:
        return True
    return pattern.rstrip("?") == actual


def _applies(mw: _Mw, method: str, path: str) -> bool | None:
    if "ALL" not in mw.methods and method not in mw.methods:
        return False
    target = _segments(path)
    result: bool | None = False
    for p in mw.paths:
        if p is None:
            result = None
            continue
        pat = _segments(p)
        if pat and pat[-1] in {"*", "(.*)"}:
            pat, wildcard = pat[:-1], True
        else:
            wildcard = not mw.exact
        if len(pat) > len(target) or (not wildcard and len(pat) != len(target)):
            continue
        if all(_seg_match(a, b) for a, b in zip(pat, target, strict=False)):
            return True
    return result


def _exempt(exempt: list[str | re.Pattern[str] | None], path: str) -> bool:
    for x in exempt:
        if x is None:
            return True  # an exemption we cannot evaluate: do not credit the guard
        if isinstance(x, str) and _segments(x) == _segments(path):
            return True
        if isinstance(x, re.Pattern) and x.search(path):
            return True
    return False


def _options(args: list[V]) -> dict[str, str]:
    out: dict[str, str] = {}
    for a in args:
        if isinstance(a, Obj):
            for k, v in a.props.items():
                if isinstance(v, Lit):
                    out[k] = v.s
        elif isinstance(a, Lit) and a.kind == "str" and "strategy" not in out:
            out["strategy"] = a.s
    return out


def _dedupe(guards: list[GuardRef]) -> list[GuardRef]:
    seen: set[tuple[str, str]] = set()
    out = []
    for g in guards:
        k = (g.symbol, g.kind)
        if k not in seen:
            seen.add(k)
            out.append(g)
    return out


def uses_express(files: dict[str, JsFileSummary]) -> bool:
    return any(
        imp.source in {"express", "router"} for s in files.values() for imp in s.imports.values()
    )
