"""Node / TypeScript module resolution over summaries (FR-3.6), without touching node_modules.

Relative specifiers follow Node's file then directory lookup (``x``, ``x.ts``, ``x/index.ts``,
and a ``.js`` specifier that names a ``.ts`` source, as TypeScript's ESM output does). Bare
specifiers are packages; ``compilerOptions.paths`` / ``baseUrl`` from tsconfig.json map aliases
such as ``@/lib/auth``. A specifier we cannot map is reported as unresolved, never guessed.
"""

from __future__ import annotations

import json
import posixpath
import re

from authgraph.lang.js.summary import JsFileSummary

EXTS = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".mts", ".cts")
_COMMENTS = re.compile(r"//[^\n]*|/\*.*?\*/", re.S)
_TRAILING_COMMA = re.compile(r",(\s*[}\]])")


def parse_jsonc(data: bytes) -> dict[str, object]:
    """tsconfig.json allows comments and trailing commas."""
    text = data.decode("utf-8", "replace")
    out: list[str] = []
    i = 0
    # Strip comments outside strings.
    in_str = False
    while i < len(text):
        c = text[i]
        if in_str:
            out.append(c)
            if c == "\\" and i + 1 < len(text):
                out.append(text[i + 1])
                i += 1
            elif c == '"':
                in_str = False
        elif c == '"':
            in_str = True
            out.append(c)
        elif text.startswith("//", i):
            j = text.find("\n", i)
            i = len(text) if j < 0 else j
            continue
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            i = len(text) if j < 0 else j + 2
            continue
        else:
            out.append(c)
        i += 1
    try:
        v = json.loads(_TRAILING_COMMA.sub(r"\1", "".join(out)))
    except ValueError:
        return {}
    return v if isinstance(v, dict) else {}


class PathAliases:
    """``compilerOptions.paths`` of one tsconfig.json (one per project directory)."""

    def __init__(self, tsconfig_dir: str, config: dict[str, object]) -> None:
        opts = config.get("compilerOptions")
        opts = opts if isinstance(opts, dict) else {}
        base = opts.get("baseUrl")
        self.dir = tsconfig_dir
        self.base = (
            posixpath.normpath(posixpath.join(tsconfig_dir, base))
            if isinstance(base, str)
            else None
        )
        paths = opts.get("paths")
        self.paths: list[tuple[str, list[str]]] = []
        if isinstance(paths, dict):
            for k, v in paths.items():
                if isinstance(k, str) and isinstance(v, list):
                    self.paths.append((k, [x for x in v if isinstance(x, str)]))

    def candidates(self, spec: str) -> list[str]:
        root = self.base or self.dir
        out: list[str] = []
        for pattern, targets in self.paths:
            if pattern.endswith("*"):
                if spec.startswith(pattern[:-1]):
                    rest = spec[len(pattern) - 1 :]
                    out += [posixpath.join(root, t.replace("*", rest)) for t in targets]
            elif spec == pattern:
                out += [posixpath.join(root, t) for t in targets]
        if self.base is not None and not out:
            out.append(posixpath.join(self.base, spec))
        return [posixpath.normpath(p) for p in out]


class NodeResolver:
    def __init__(self, files: dict[str, JsFileSummary], tsconfigs: dict[str, PathAliases]) -> None:
        self.files = files
        self.tsconfigs = tsconfigs  # directory -> aliases
        self.unresolved: set[tuple[str, str]] = set()

    def _probe(self, base: str) -> str | None:
        base = posixpath.normpath(base)
        if base in self.files:
            return base
        stem, ext = posixpath.splitext(base)
        if ext in {".js", ".jsx", ".mjs", ".cjs"}:  # TS sources imported by their output name
            for e in (".ts", ".tsx", ".mts", ".cts"):
                if stem + e in self.files:
                    return stem + e
        for e in EXTS:
            if base + e in self.files:
                return base + e
        for e in EXTS:
            if f"{base}/index{e}" in self.files:
                return f"{base}/index{e}"
        return None

    def _aliases_for(self, importer: str) -> PathAliases | None:
        d = posixpath.dirname(importer)
        while True:
            if d in self.tsconfigs:
                return self.tsconfigs[d]
            if not d:
                return None
            d = posixpath.dirname(d)

    def resolve(self, importer: str, spec: str) -> str | None:
        """Repo path of the module, or None for a package / unresolvable specifier."""
        if spec.startswith((".", "/")):
            base = (
                spec.lstrip("/")
                if spec.startswith("/")
                else posixpath.join(posixpath.dirname(importer), spec)
            )
            hit = self._probe(base)
            if hit is None:
                self.unresolved.add((importer, spec))
            return hit
        aliases = self._aliases_for(importer)
        if aliases is not None:
            for cand in aliases.candidates(spec):
                hit = self._probe(cand)
                if hit is not None:
                    return hit
            if any(spec.startswith(p.rstrip("*")) for p, _ in aliases.paths):
                self.unresolved.add((importer, spec))
        return None

    @staticmethod
    def package_of(spec: str) -> str:
        parts = spec.split("/")
        return "/".join(parts[:2]) if spec.startswith("@") and len(parts) > 1 else parts[0]

    def is_local_alias(self, importer: str, spec: str) -> bool:
        """An alias-looking specifier (``@/x``, ``~/x``, ``src/x``) that did not resolve."""
        return spec.startswith(("@/", "~/", "#")) or (importer, spec) in self.unresolved
