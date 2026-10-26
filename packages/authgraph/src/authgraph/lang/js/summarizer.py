"""JavaScript / TypeScript summarizer on tree-sitter (FR-3.1, FR-3.6; PLAN.md Phase 3).

Parses with tree-sitter only: scanned code is never loaded into Node (ADR 005). Grammar node and
field names verified against tree-sitter-javascript 0.25.0 / tree-sitter-typescript 0.23.2
(``src/node-types.json``) and the py-tree-sitter 0.26 ``Node`` API.
"""

from __future__ import annotations

import re
from collections.abc import Iterator

import tree_sitter as ts
import tree_sitter_javascript as tsjs
import tree_sitter_typescript as tsts

from authgraph.lang.js.summary import JsEvent, JsFileSummary, JsFunction, JsImport, JsValue

JS_SUFFIXES = (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts")
_LANGS = {
    "js": ts.Language(tsjs.language()),
    "ts": ts.Language(tsts.language_typescript()),
    "tsx": ts.Language(tsts.language_tsx()),
}
FUNCTION_TYPES = frozenset(
    {
        "function_declaration",
        "generator_function_declaration",
        "function_expression",
        "function",
        "generator_function",
        "arrow_function",
        "method_definition",
    }
)
# TS wrappers that do not change the runtime value.
TRANSPARENT = frozenset(
    {
        "parenthesized_expression",
        "as_expression",
        "satisfies_expression",
        "non_null_expression",
        "type_assertion",
        "await_expression",
    }
)
NESTED_BLOCKS = frozenset(
    {
        "statement_block",
        "if_statement",
        "else_clause",
        "try_statement",
        "catch_clause",
        "finally_clause",
        "for_statement",
        "for_in_statement",
        "while_statement",
        "do_statement",
        "switch_statement",
        "switch_body",
        "switch_case",
        "switch_default",
        "labeled_statement",
    }
)
STATUS_NAMES = {
    "UNAUTHORIZED": 401,
    "UNAUTHENTICATED": 401,
    "FORBIDDEN": 403,
    "NOT_FOUND": 404,
}
STATUS_CALLS = frozenset({"status", "sendStatus", "code", "writeHead"})
SEND_CALLS = frozenset(
    {"send", "json", "end", "render", "redirect", "sendFile", "download", "jsonp", "sendStatus"}
)
ERROR_CTOR = re.compile(r"(Error|Exception|createError|HttpError|httpError)$")
ERROR_CLASS_STATUS = (
    (re.compile(r"(Unauthori[sz]ed|Unauthenticated|NotAuthenticated)", re.I), 401),
    (re.compile(r"(Forbidden|AccessDenied|PermissionDenied)", re.I), 403),
)
BOOM = {"unauthorized": 401, "forbidden": 403}
ROLE_ATTR = re.compile(
    r"\.(role|roles|isAdmin|is_admin|admin|permissions?|rights|scopes?|groups|isStaff|"
    r"isSuperuser|userRights|claims)\b|\b(roles?|permissions?|rights|userRights|scopes?)\b"
)
ID_PARAM = re.compile(r"\b(req|request)\.params\.\w+|\bparams\.\w*[iI]d\b")
PRINCIPAL_ID = re.compile(
    r"\b(user|principal|account|me|auth|currentUser|session)\w*\.(id|_id|sub)\b"
)
MAX_CALLS = 200


def language_for(path: str) -> str | None:
    if path.endswith((".ts", ".mts", ".cts")):
        return "ts" if not path.endswith(".d.ts") else None
    if path.endswith(".tsx"):
        return "tsx"
    if path.endswith((".js", ".jsx", ".mjs", ".cjs")):
        return "js"  # the JS grammar includes JSX
    return None


def _text(n: ts.Node | None) -> str:
    return n.text.decode("utf-8", "replace") if n is not None and n.text is not None else ""


def _unwrap(n: ts.Node) -> ts.Node:
    while n.type in TRANSPARENT and n.named_children:
        n = n.named_children[0] if n.type != "type_assertion" else n.named_children[-1]
    return n


def _string(n: ts.Node) -> str | None:
    if n.type == "string":
        return "".join(_text(c) for c in n.named_children if c.type == "string_fragment")
    if n.type == "template_string":
        if any(c.type == "template_substitution" for c in n.named_children):
            return None
        return "".join(_text(c) for c in n.named_children if c.type == "string_fragment")
    return None


class _Summarizer:
    def __init__(self, path: str, blob_sha: str) -> None:
        self.path = path
        self.out = JsFileSummary(path=path, blob_sha=blob_sha)

    # ---- values -------------------------------------------------------------------------
    def value(self, n: ts.Node | None) -> JsValue:
        if n is None:
            return JsValue(k="other", s="none")
        n = _unwrap(n)
        line = n.start_point[0] + 1
        t = n.type
        s = _string(n)
        if s is not None:
            return JsValue(k="str", s=s, line=line)
        if t == "template_string":
            parts: list[JsValue] = []
            for c in n.named_children:
                if c.type == "string_fragment":
                    parts.append(JsValue(k="str", s=_text(c), line=line))
                elif c.type == "template_substitution" and c.named_children:
                    parts.append(self.value(c.named_children[0]))
            return JsValue(k="tmpl", args=parts, line=line)
        if t == "number":
            return JsValue(k="num", s=_text(n), line=line)
        if t in {"true", "false"}:
            return JsValue(k="bool", s=t, line=line)
        if t in {"null", "undefined"}:
            return JsValue(k="null", line=line)
        if t in {"identifier", "property_identifier", "shorthand_property_identifier"}:
            return JsValue(k="id", s=_text(n), line=line)
        if t == "this":
            return JsValue(k="id", s="this", line=line)
        if t == "member_expression":
            return JsValue(
                k="member",
                s=_text(n.child_by_field_name("property")),
                obj=self.value(n.child_by_field_name("object")),
                line=line,
            )
        if t == "subscript_expression":
            idx = n.child_by_field_name("index")
            key = _string(idx) if idx is not None else None
            if key is not None:
                return JsValue(
                    k="member", s=key, obj=self.value(n.child_by_field_name("object")), line=line
                )
            return JsValue(k="other", s=t, line=line)
        if t in {"call_expression", "new_expression"}:
            callee = n.child_by_field_name("function" if t == "call_expression" else "constructor")
            args_node = n.child_by_field_name("arguments")
            args = [self.value(a) for a in args_node.named_children] if args_node else []
            if callee is not None and callee.type == "import":
                return JsValue(k="call", obj=JsValue(k="id", s="require"), args=args, line=line)
            return JsValue(
                k="call" if t == "call_expression" else "new",
                obj=self.value(callee),
                args=args,
                line=line,
            )
        if t in FUNCTION_TYPES:
            return JsValue(k="func", s=self.function(n), line=line)
        if t == "array":
            return JsValue(k="array", args=[self.value(c) for c in n.named_children], line=line)
        if t == "object":
            props: dict[str, JsValue] = {}
            for c in n.named_children:
                if c.type == "pair":
                    keynode = c.child_by_field_name("key")
                    k = _string(keynode) if keynode is not None else None
                    if (
                        k is None
                        and keynode is not None
                        and keynode.type
                        in {
                            "property_identifier",
                            "number",
                        }
                    ):
                        k = _text(keynode)
                    if k is not None:
                        props[k] = self.value(c.child_by_field_name("value"))
                elif c.type == "shorthand_property_identifier":
                    props[_text(c)] = JsValue(k="id", s=_text(c), line=line)
                elif c.type == "method_definition":
                    props[_text(c.child_by_field_name("name"))] = JsValue(
                        k="func", s=self.function(c), line=line
                    )
            return JsValue(k="object", props=props, line=line)
        if t == "regex":
            return JsValue(k="regex", s=_text(n.child_by_field_name("pattern")), line=line)
        if t == "spread_element" and n.named_children:
            return JsValue(k="spread", obj=self.value(n.named_children[0]), line=line)
        if t == "assignment_expression":
            return self.value(n.child_by_field_name("right"))
        if t == "ternary_expression":
            return JsValue(k="other", s="ternary", line=line)
        return JsValue(k="other", s=t, line=line)

    # ---- functions ------------------------------------------------------------------------
    def function(self, n: ts.Node, name: str = "") -> str:
        line = n.start_point[0] + 1
        nm = name or _text(n.child_by_field_name("name"))
        fid = f"{self.path}#{nm or 'anon'}@{line}:{n.start_point[1]}"
        if fid in self.out.functions:
            return fid
        params: list[str] = []
        ps = n.child_by_field_name("parameters")
        if ps is not None:
            params = [self._param_name(p) for p in ps.named_children if p.type != "comment"]
        elif (p1 := n.child_by_field_name("parameter")) is not None:
            params = [_text(p1)]
        fn = JsFunction(id=fid, name=nm, params=params, line=line)
        self.out.functions[fid] = fn
        body = n.child_by_field_name("body")
        if body is None:
            return fid
        if body.type == "statement_block":
            self.block(body, fn)
        else:  # concise arrow body is the return value
            fn.returns.append(self.value(body))
        self.features(body, fn)
        return fid

    def _param_name(self, p: ts.Node) -> str:
        if p.type in {"required_parameter", "optional_parameter"}:
            p = p.child_by_field_name("pattern") or p
        if p.type == "assignment_pattern":
            p = p.child_by_field_name("left") or p
        if p.type == "rest_pattern" and p.named_children:
            p = p.named_children[0]
        if p.type == "object_pattern":
            # Destructured parameter, recorded as "{key:local,...}" for the interpreter.
            keys = []
            for c in p.named_children:
                if c.type == "shorthand_property_identifier_pattern":
                    keys.append(f"{_text(c)}:{_text(c)}")
                elif c.type == "pair_pattern":
                    v = c.child_by_field_name("value")
                    if v is not None and v.type == "identifier":
                        keys.append(f"{_text(c.child_by_field_name('key'))}:{_text(v)}")
                elif c.type == "object_assignment_pattern":
                    left = _text(c.child_by_field_name("left"))
                    keys.append(f"{left}:{left}")
            return "{" + ",".join(keys) + "}"
        return _text(p) if p.type == "identifier" else ""

    def block(self, n: ts.Node, fn: JsFunction) -> None:
        # Hoist function declarations so calls before the declaration resolve.
        for c in n.named_children:
            d = c.child_by_field_name("declaration") if c.type == "export_statement" else c
            if d is not None and d.type in {
                "function_declaration",
                "generator_function_declaration",
            }:
                fid = self.function(d)
                nm = _text(d.child_by_field_name("name"))
                fn.events.append(
                    JsEvent(
                        k="assign",
                        name=nm,
                        value=JsValue(k="func", s=fid, line=d.start_point[0] + 1),
                        line=d.start_point[0] + 1,
                    )
                )
        for c in n.named_children:
            self.statement(c, fn)

    def statement(self, n: ts.Node, fn: JsFunction) -> None:
        t = n.type
        line = n.start_point[0] + 1
        if t == "expression_statement" and n.named_children:
            e = _unwrap(n.named_children[0])
            if e.type in {"assignment_expression", "augmented_assignment_expression"}:
                left = self.value(e.child_by_field_name("left"))
                target = left.dotted()
                if target:
                    fn.events.append(
                        JsEvent(
                            k="assign",
                            name=target,
                            value=self.value(e.child_by_field_name("right")),
                            line=line,
                        )
                    )
                    if fn.id == self.out.module_fn:
                        self._module_export(target, e.child_by_field_name("right"))
            elif e.type in {"call_expression", "new_expression"}:
                fn.events.append(JsEvent(k="expr", value=self.value(e), line=line))
            elif e.type == "sequence_expression":
                for c in e.named_children:
                    if _unwrap(c).type == "call_expression":
                        fn.events.append(JsEvent(k="expr", value=self.value(c), line=line))
        elif t in {"lexical_declaration", "variable_declaration"}:
            for d in n.named_children:
                if d.type == "variable_declarator":
                    self.declarator(d, fn)
        elif t in {"function_declaration", "generator_function_declaration"}:
            pass  # hoisted in block()
        elif t == "class_declaration":
            nm = _text(n.child_by_field_name("name"))
            if nm:
                fn.events.append(
                    JsEvent(k="assign", name=nm, value=JsValue(k="other", s="class"), line=line)
                )
            body = n.child_by_field_name("body")
            for m in body.named_children if body is not None else []:
                if m.type == "method_definition":
                    self.function(m)
        elif t == "return_statement":
            if n.named_children:
                fn.returns.append(self.value(n.named_children[0]))
        elif t == "import_statement":
            self.import_statement(n)
        elif t == "export_statement":
            self.export_statement(n, fn)
        elif t == "for_in_statement" and any(c.type == "of" for c in n.children):
            self.for_of(n, fn)
        elif t in NESTED_BLOCKS:
            for c in n.named_children:
                if (
                    c.type in NESTED_BLOCKS
                    or c.type.endswith("statement")
                    or c.type
                    in {
                        "lexical_declaration",
                        "variable_declaration",
                        "function_declaration",
                    }
                ) or c.type == "statement_block":
                    self.statement(c, fn)

    def for_of(self, n: ts.Node, fn: JsFunction) -> None:
        """``for (const x of xs) {body}`` is recorded as ``xs.forEach((x) => {body})``."""
        left = n.child_by_field_name("left")
        right = n.child_by_field_name("right")
        body = n.child_by_field_name("body")
        if left is None or right is None or body is None:
            return
        line = n.start_point[0] + 1
        fid = f"{self.path}#for@{line}:{n.start_point[1]}"
        loop = JsFunction(id=fid, name="", params=[self._param_name(left)], line=line)
        self.out.functions[fid] = loop
        if body.type == "statement_block":
            self.block(body, loop)
        else:
            self.statement(body, loop)
        call = JsValue(
            k="call",
            obj=JsValue(k="member", s="forEach", obj=self.value(right), line=line),
            args=[JsValue(k="func", s=fid, line=line)],
            line=line,
        )
        fn.events.append(JsEvent(k="expr", value=call, line=line))

    def declarator(self, d: ts.Node, fn: JsFunction) -> None:
        name = d.child_by_field_name("name")
        val = d.child_by_field_name("value")
        if name is None or val is None:
            return
        line = d.start_point[0] + 1
        if name.type == "identifier":
            nm = _text(name)
            inner = _unwrap(val)
            v = (
                JsValue(k="func", s=self.function(inner, nm), line=line)
                if inner.type in FUNCTION_TYPES
                else self.value(val)
            )
            fn.events.append(JsEvent(k="assign", name=nm, value=v, line=line))
            self._require_import(nm, v, "*")
        elif name.type == "object_pattern":
            src = self.value(val)
            for p in name.named_children:
                if p.type == "shorthand_property_identifier_pattern":
                    key = local = _text(p)
                elif p.type == "pair_pattern":
                    key = _text(p.child_by_field_name("key"))
                    vnode = p.child_by_field_name("value")
                    if vnode is not None and vnode.type == "assignment_pattern":
                        vnode = vnode.child_by_field_name("left")
                    if vnode is None or vnode.type != "identifier":
                        continue
                    local = _text(vnode)
                elif p.type == "object_assignment_pattern":
                    left = p.child_by_field_name("left")
                    key = local = _text(left)
                else:
                    continue
                v = JsValue(k="member", s=key, obj=src, line=line)
                fn.events.append(JsEvent(k="assign", name=local, value=v, line=line))
                self._require_import(local, src, key)

    def _require_import(self, local: str, v: JsValue, name: str) -> None:
        """``const x = require('m')`` / ``const {a} = require('m')`` are imports too."""
        if (
            v.k == "call"
            and v.obj is not None
            and v.obj.k == "id"
            and v.obj.s == "require"
            and v.args
            and v.args[0].k == "str"
        ):
            self.out.imports[local] = JsImport(source=v.args[0].s, name=name, line=v.line)

    def import_statement(self, n: ts.Node) -> None:
        src_node = n.child_by_field_name("source")
        line = n.start_point[0] + 1
        for c in n.named_children:
            if c.type == "import_require_clause":  # import x = require('m')
                ident = c.named_children[0] if c.named_children else None
                src = c.child_by_field_name("source")
                if ident is not None and src is not None:
                    self.out.imports[_text(ident)] = JsImport(
                        source=_string(src) or "", name="*", line=line
                    )
        if src_node is None:
            return
        source = _string(src_node) or ""
        clause = next((c for c in n.named_children if c.type == "import_clause"), None)
        if clause is None:
            return
        for c in clause.named_children:
            if c.type == "identifier":
                self.out.imports[_text(c)] = JsImport(source=source, name="default", line=line)
            elif c.type == "namespace_import" and c.named_children:
                self.out.imports[_text(c.named_children[0])] = JsImport(
                    source=source, name="*", line=line
                )
            elif c.type == "named_imports":
                for spec in c.named_children:
                    if spec.type != "import_specifier":
                        continue
                    nm = _text(spec.child_by_field_name("name"))
                    alias = _text(spec.child_by_field_name("alias")) or nm
                    self.out.imports[alias] = JsImport(source=source, name=nm, line=line)

    def export_statement(self, n: ts.Node, fn: JsFunction) -> None:
        line = n.start_point[0] + 1
        decl = n.child_by_field_name("declaration")
        val = n.child_by_field_name("value")
        src = n.child_by_field_name("source")
        if decl is not None:
            self.statement(decl, fn)
            if decl.type in {"lexical_declaration", "variable_declaration"}:
                for d in decl.named_children:
                    nm = d.child_by_field_name("name") if d.type == "variable_declarator" else None
                    if nm is not None and nm.type == "identifier":
                        self.out.exports[_text(nm)] = JsValue(k="id", s=_text(nm), line=line)
            elif (nm := decl.child_by_field_name("name")) is not None:
                self.out.exports[_text(nm)] = JsValue(k="id", s=_text(nm), line=line)
            return
        is_default = any(c.type == "default" for c in n.children)
        if val is not None or (is_default and n.named_children):
            node = val if val is not None else n.named_children[-1]
            inner = _unwrap(node)
            if inner.type in FUNCTION_TYPES:
                self.out.exports["default"] = JsValue(k="func", s=self.function(inner), line=line)
            else:
                self.out.exports["default"] = self.value(node)
                if inner.type in {"call_expression", "new_expression"}:
                    # `export default Router().use(...)` registers routes as it evaluates.
                    fn.events.append(
                        JsEvent(k="assign", name="#default", value=self.value(node), line=line)
                    )
                    self.out.exports["default"] = JsValue(k="id", s="#default", line=line)
            return
        clause = next((c for c in n.named_children if c.type == "export_clause"), None)
        source = _string(src) if src is not None else None
        if clause is not None:
            for spec in clause.named_children:
                if spec.type != "export_specifier":
                    continue
                orig = _text(spec.child_by_field_name("name"))
                alias = _text(spec.child_by_field_name("alias")) or orig
                if source is not None:
                    self.out.imports[f"#reexport:{alias}"] = JsImport(
                        source=source, name=orig, line=line
                    )
                    self.out.exports[alias] = JsValue(k="id", s=f"#reexport:{alias}", line=line)
                else:
                    self.out.exports[alias] = JsValue(k="id", s=orig, line=line)
        elif source is not None:
            self.out.reexports.append(JsImport(source=source, name="*", line=line))
        else:
            # TS `export = router`
            for c in n.named_children:
                if c.type in {"identifier", "call_expression", "member_expression"}:
                    self.out.exports["default"] = self.value(c)

    def _module_export(self, target: str, right: ts.Node | None) -> None:
        if target in {"module.exports", "exports"}:
            v = self.value(right)
            if v.k == "object":
                for k, pv in v.props.items():
                    self.out.exports.setdefault(k, pv)
            self.out.exports["default"] = (
                v if v.k != "func" else JsValue(k="func", s=v.s, line=v.line)
            )
        elif target.startswith(("module.exports.", "exports.")):
            self.out.exports[target.rsplit(".", 1)[-1]] = self.value(right)

    # ---- guard features ---------------------------------------------------------------------
    def features(self, body: ts.Node, fn: JsFunction) -> None:
        next_name = fn.params[2] if len(fn.params) >= 3 and fn.params[2] else "next"
        res_name = fn.params[1] if len(fn.params) >= 2 and fn.params[1] else "res"
        statuses: set[int] = set()
        calls: list[str] = []
        for c in _walk(body):
            t = c.type
            if t in {"call_expression", "new_expression"}:
                callee = c.child_by_field_name(
                    "function" if t == "call_expression" else "constructor"
                )
                if callee is None:
                    continue
                cv = self.value(callee)
                dotted = cv.dotted() or ""
                last = dotted.rsplit(".", 1)[-1] if dotted else (cv.s if cv.k == "member" else "")
                args_node = c.child_by_field_name("arguments")
                args = list(args_node.named_children) if args_node is not None else []
                if dotted and len(calls) < MAX_CALLS:
                    calls.append(dotted)
                elif cv.k == "member" and len(calls) < MAX_CALLS:
                    calls.append("?." + cv.s)
                if last in STATUS_CALLS and args:
                    statuses |= _status_of(args[0])
                if ERROR_CTOR.search(last) or (last.startswith("create") and "rror" in last):
                    for a in args:
                        statuses |= _status_of(a)
                    for rx, code in ERROR_CLASS_STATUS:
                        if rx.search(last):
                            statuses.add(code)
                elif t == "new_expression":
                    for rx, code in ERROR_CLASS_STATUS:
                        if rx.search(last):
                            statuses.add(code)
                if dotted.startswith("Boom.") and last in BOOM:
                    statuses.add(BOOM[last])
                if dotted.startswith(("createError.", "createHttpError.", "httpErrors.")):
                    for rx, code in ERROR_CLASS_STATUS:
                        if rx.search(last):
                            statuses.add(code)
                if any(a.type == "identifier" and _text(a) == next_name for a in args):
                    fn.forwards_next = True
                if dotted == next_name:
                    real = [a for a in args if a.type != "comment"]
                    if not real:
                        fn.calls_next = True
                    elif _string(real[0]) not in {"route", "router"}:
                        fn.next_error = True
                root = dotted.split(".", 1)[0] if dotted else _root(cv)
                if last in SEND_CALLS and root in {res_name, "res", "response", "reply"}:
                    fn.sends = True
                if root in {"console", "logger", "log", "winston", "pino"}:
                    fn.logs = True
            elif t == "binary_expression":
                op = _text(c.child_by_field_name("operator"))
                if op in {"===", "!==", "==", "!=", "in"}:
                    txt = _text(c)
                    if ROLE_ATTR.search(txt):
                        fn.role_compare = True
                    if ID_PARAM.search(txt) and (PRINCIPAL_ID.search(txt) or "user" in txt.lower()):
                        fn.owner_compare = True
            elif t == "throw_statement" and c.named_children:
                statuses |= _status_of(c.named_children[0])
        if any(x.endswith((".includes", ".some", ".every", ".indexOf")) for x in calls):
            txt = _text(body)
            if ROLE_ATTR.search(txt):
                fn.role_compare = True
        fn.statuses = sorted(s for s in statuses if 400 <= s < 500)
        fn.calls = calls


def _root(v: JsValue) -> str:
    while v.obj is not None and v.k in {"member", "call"}:
        v = v.obj
    return v.s if v.k == "id" else ""


def _walk(n: ts.Node) -> Iterator[ts.Node]:
    stack = [n]
    while stack:
        c = stack.pop()
        yield c
        stack.extend(reversed(c.named_children))


def _status_of(n: ts.Node) -> set[int]:
    """Status codes named anywhere in an argument (``401``, ``httpStatus.UNAUTHORIZED``)."""
    out: set[int] = set()
    for c in _walk(n):
        if c.type == "number":
            try:
                v = int(_text(c))
            except ValueError:
                continue
            if 400 <= v < 500:
                out.add(v)
        elif c.type in {"property_identifier", "identifier"}:
            name = _text(c)
            if name.upper() in STATUS_NAMES:
                out.add(STATUS_NAMES[name.upper()])
            for rx, code in ERROR_CLASS_STATUS:
                if rx.fullmatch(name) or (
                    name[:1].isupper() and rx.search(name) and "Error" in name
                ):
                    out.add(code)
    return out


def summarize(path: str, data: bytes, blob_sha: str) -> JsFileSummary:
    lang = language_for(path)
    s = _Summarizer(path, blob_sha)
    if lang is None:
        s.out.parse_error = "unsupported file type"
        return s.out
    try:
        tree = ts.Parser(_LANGS[lang]).parse(data)
    except Exception as e:  # pragma: no cover - parser errors are reported, never raised
        s.out.parse_error = f"parse failed: {e}"
        return s.out
    root = tree.root_node
    mod = JsFunction(id=f"{path}#<module>@0", name="<module>", line=0)
    s.out.module_fn = mod.id
    s.out.functions[mod.id] = mod
    s.block(root, mod)
    if root.has_error:
        # Partial trees are still summarized; the error is reported in coverage.
        s.out.parse_error = None if _error_ratio(root) < 0.2 else "syntax errors"
    return s.out


def _error_ratio(root: ts.Node) -> float:
    total = err = 0
    for c in root.named_children:
        total += 1
        err += c.has_error
    return err / total if total else 0.0
