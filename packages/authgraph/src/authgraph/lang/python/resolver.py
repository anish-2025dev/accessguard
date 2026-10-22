"""Own Python import and symbol resolver (PLAN.md §6.3 step 3). Pure lookups over summaries."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from posixpath import dirname
from typing import Literal

from authgraph.lang.python.summary import Assign, ClassInfo, FileSummary, Function, Value

TargetKind = Literal[
    "module", "function", "class", "assign", "instance_attr", "external", "param", "unresolved"
]
MAX_DEPTH = 24


@dataclass(frozen=True)
class Target:
    kind: TargetKind
    path: str = ""  # file of the definition
    name: str = ""  # qualname / assign target / external dotted / attribute
    scope: str = ""  # scope of an assign target

    @property
    def summary_key(self) -> tuple[str, str, str]:
        return (self.path, self.scope, self.name)


class ProjectIndex:
    """All file summaries of one commit plus module and symbol resolution over them."""

    def __init__(self, summaries: dict[str, FileSummary]) -> None:
        self.files = summaries
        self.by_module: dict[str, list[str]] = defaultdict(list)
        for path in summaries:
            if not path.endswith(".py"):
                continue
            parts = path[:-3].split("/")
            if parts[-1] == "__init__":
                parts = parts[:-1]
            for i in range(len(parts)):
                self.by_module[".".join(parts[i:])].append(path)
        self.unresolved_imports = 0

    # --- modules ---------------------------------------------------------------------------

    def module_path(self, importer: str, module: str, level: int = 0) -> str | None:
        if level:
            base = dirname(importer)
            for _ in range(level - 1):
                base = dirname(base)
            rel = "/".join(p for p in [base, *module.split(".")] if p) if module else base
            for cand in (f"{rel}.py", f"{rel}/__init__.py"):
                if cand in self.files:
                    return cand
            return None
        cands = self.by_module.get(module, [])
        if not cands:
            return None
        if len(cands) == 1:
            return cands[0]
        depth = module.count(".") + 1

        def root_of(p: str) -> str:
            parts = p.split("/")
            n = depth + (1 if parts[-1] == "__init__.py" else 0)
            return "/".join(parts[:-n])

        # Prefer the candidate whose package root is the closest ancestor of the importer.
        best = max(
            cands,
            key=lambda c: (
                importer.startswith(root_of(c) + "/") or root_of(c) == "",
                len(root_of(c)) if importer.startswith(root_of(c)) else -1,
                -len(c),
            ),
        )
        return best

    def module_name(self, path: str) -> str:
        s = self.files.get(path)
        return s.module if s else path

    # --- symbols ---------------------------------------------------------------------------

    def resolve(self, path: str, scope: str, dotted: str, depth: int = 0) -> Target:
        if depth > MAX_DEPTH:
            return Target("unresolved", path, dotted)
        head, _, rest = dotted.partition(".")
        t = self._lookup(path, scope, head, depth)
        for attr in rest.split(".") if rest else []:
            t = self._attr(t, attr, depth)
        return t

    def _scopes(self, scope: str) -> list[str]:
        parts = scope.split(".") if scope else []
        return [".".join(parts[:i]) for i in range(len(parts), -1, -1)]

    def _lookup(self, path: str, scope: str, name: str, depth: int) -> Target:
        s = self.files.get(path)
        if s is None:
            return Target("unresolved", path, name)
        for sc in self._scopes(scope):
            qual = f"{sc}.{name}" if sc else name
            if qual in s.functions:
                return Target("function", path, qual)
            if qual in s.classes:
                return Target("class", path, qual)
            assign = self._last_assign(s, sc, name)
            if assign is not None:
                return self._from_assign(path, assign, depth)
            for imp in reversed(s.imports):
                if imp.scope == sc and imp.asname == name:
                    return self._from_import(path, imp.module, imp.name, imp.level, depth)
            fn = s.functions.get(sc) if sc else None
            if fn is not None and any(p.name == name for p in fn.params):
                return Target("param", path, name, sc)
            for imp in s.imports:
                if imp.scope == sc and imp.name == "*":
                    mod = self.module_path(path, imp.module, imp.level)
                    if mod:
                        t = self._lookup(mod, "", name, depth + 1)
                        if t.kind != "unresolved":
                            return t
        if s.is_package:  # `from pkg import sub` where sub is a submodule
            sub = self.module_path(path, name, 1)
            if sub:
                return Target("module", sub)
        return Target("unresolved", path, name)

    @staticmethod
    def _last_assign(s: FileSummary, scope: str, name: str) -> Assign | None:
        found = None
        for a in s.assigns:
            if a.scope == scope and a.target == name:
                found = a
        return found

    def _from_assign(self, path: str, a: Assign, depth: int) -> Target:
        if a.value.kind == "name" and a.value.dotted and a.value.dotted != a.target:
            t = self.resolve(path, a.scope, a.value.dotted, depth + 1)
            if t.kind != "unresolved":
                return t
        return Target("assign", path, a.target, a.scope)

    def _from_import(
        self, path: str, module: str, name: str | None, level: int, depth: int
    ) -> Target:
        if name is None:  # `import a.b` binds `a`; `import a.b as x` binds a.b
            mod = self.module_path(path, module, level)
            if mod is None:
                self.unresolved_imports += 1
                return Target("external", "", module)
            return Target("module", mod)
        mod = self.module_path(path, module, level)
        if mod is None:
            if level == 0:
                return Target("external", "", f"{module}.{name}")
            self.unresolved_imports += 1
            return Target("unresolved", path, name)
        sub = self.module_path(mod, name, 1) if mod.endswith("__init__.py") else None
        t = self._lookup(mod, "", name, depth + 1)
        if t.kind == "unresolved" and sub:
            return Target("module", sub)
        return t

    def _attr(self, t: Target, attr: str, depth: int) -> Target:
        if t.kind == "module":
            s = self.files[t.path]
            if s.is_package:
                sub = self.module_path(t.path, attr, 1)
                inner = self._lookup(t.path, "", attr, depth + 1)
                if inner.kind == "unresolved" and sub:
                    return Target("module", sub)
                return inner
            return self._lookup(t.path, "", attr, depth + 1)
        if t.kind == "external":
            return Target("external", "", f"{t.name}.{attr}")
        if t.kind == "class":
            s = self.files[t.path]
            qual = f"{t.name}.{attr}"
            if qual in s.functions:
                return Target("function", t.path, qual)
            return Target("instance_attr", t.path, qual)
        if t.kind == "assign":
            return Target("instance_attr", t.path, f"{t.name}.{attr}", t.scope)
        if t.kind == "instance_attr":
            return Target("instance_attr", t.path, f"{t.name}.{attr}", t.scope)
        return Target("unresolved", t.path, f"{t.name}.{attr}")

    # --- accessors -------------------------------------------------------------------------

    def function(self, t: Target) -> Function | None:
        s = self.files.get(t.path)
        return s.functions.get(t.name) if s and t.kind == "function" else None

    def klass(self, t: Target) -> ClassInfo | None:
        s = self.files.get(t.path)
        return s.classes.get(t.name) if s and t.kind == "class" else None

    def assign(self, t: Target) -> Assign | None:
        s = self.files.get(t.path)
        if s is None or t.kind != "assign":
            return None
        return self._last_assign(s, t.scope, t.name)

    def qualified(self, t: Target) -> str:
        if t.kind == "external":
            return t.name
        return f"{self.module_name(t.path)}.{t.name}" if t.name else self.module_name(t.path)

    def class_fields(self, t: Target, depth: int = 0) -> dict[str, Value | None]:
        """Annotated fields of a (pydantic) class including resolvable base classes."""
        info = self.klass(t)
        if info is None or depth > 5:
            return {}
        fields: dict[str, Value | None] = {}
        for base in info.bases:
            bt = self.resolve(t.path, "", base)
            fields.update(self.class_fields(bt, depth + 1))
        fields.update(info.fields)
        return fields

    def callee(self, path: str, scope: str, v: Value) -> Target:
        if v.dotted is None:
            return Target("unresolved", path, "<expr>")
        return self.resolve(path, scope, v.dotted)

    def eval_str(self, path: str, scope: str, v: Value | None, depth: int = 0) -> str | None:
        """Constant-fold a string expression (prefixes, paths). None when not static."""
        if v is None or depth > 10:
            return None
        if v.kind == "const" and isinstance(v.const, str):
            return v.const
        if v.kind == "fstring":
            parts = [self.eval_str(path, scope, p, depth + 1) for p in v.items]
            return None if any(p is None for p in parts) else "".join(p or "" for p in parts)
        if v.kind == "name" and v.dotted:
            t = self.resolve(path, scope, v.dotted)
            return self.eval_target_str(t, depth + 1)
        return None

    def eval_target_str(self, t: Target, depth: int) -> str | None:
        if t.kind == "assign":
            a = self.assign(t)
            return self.eval_str(t.path, t.scope, a.value, depth + 1) if a else None
        if t.kind == "instance_attr":
            # settings.API_V1_STR where settings = Settings(): the class attribute default.
            obj, _, attr = t.name.rpartition(".")
            base = Target("assign", t.path, obj, t.scope)
            a = self.assign(base)
            cls_t: Target | None = None
            if a and a.value.kind == "call" and a.value.dotted:
                cls_t = self.resolve(t.path, a.scope, a.value.dotted)
            elif a is None:
                cls_t = self.resolve(t.path, "", obj) if obj else None
            if cls_t and cls_t.kind == "class":
                fields = self.class_fields(cls_t)
                return self.eval_str(cls_t.path, "", fields.get(attr), depth + 1)
        return None
