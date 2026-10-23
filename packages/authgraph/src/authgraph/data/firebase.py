"""Firebase security rules (FR-3.9): own parser for ``firestore.rules`` / ``storage.rules`` and
``database.rules.json``; nothing is evaluated or executed.

Rules language reference: https://firebase.google.com/docs/rules/rules-language (``service``,
nested ``match`` blocks with ``{wildcard}`` / ``{rest=**}`` segments, ``function`` declarations,
``allow <ops>: if <condition>;`` where a missing condition allows unconditionally).
Realtime Database: https://firebase.google.com/docs/database/security (``.read`` / ``.write``
values are booleans or expression strings, nested under path keys, ``$wildcards``).

Findings (AG-DATA-003):
* ``firebase_open`` (deterministic): ``allow`` without a condition, ``if true``, or the
  test-mode time bomb ``request.time < timestamp.date(...)``: open to everyone.
* ``firebase_auth_only`` (heuristic): the condition only checks that a user is signed in
  (``request.auth != null``, or a function that does only that): any user can reach every
  document under the path.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from authgraph.facts.models import DataExposure, Loc
from authgraph.workspace.tree import SourceTree

RULE_FILES = re.compile(r"(^|/)(firestore|storage)[\w.-]*\.rules$")
RTDB_FILES = re.compile(r"(^|/)database[\w.-]*\.rules\.json$")
TOKEN = re.compile(
    r"""\s+|//[^\n]*|/\*.*?\*/|(?P<str>'(?:\\.|[^'\\])*'|"(?:\\.|[^"\\])*")"""
    # A path (`/users/{userId}`, `/databases/$(database)/documents`) is one token.
    r"""|(?P<path>/[^\s;]+)|(?P<punct>[{}();:,])"""
    r"""|(?P<word>[^\s{}();:,'"]+)""",
    re.S,
)
AUTH_ONLY = re.compile(
    r"^\(?\s*(request\.auth|request\.auth\.uid|auth|auth\.uid)\s*!==?\s*null\s*\)?$"
)
TIME_BOMB = re.compile(r"^request\.time\s*<\s*timestamp\.date\(\s*\d+\s*,\s*\d+\s*,\s*\d+\s*\)$")
WRITE_OPS = frozenset({"write", "create", "update", "delete"})


@dataclass
class Tok:
    kind: str
    text: str
    line: int


@dataclass
class Allow:
    path: str
    ops: list[str]
    condition: str | None
    line: int


@dataclass
class Ruleset:
    service: str = ""
    allows: list[Allow] = field(default_factory=list)
    functions: dict[str, str] = field(default_factory=dict)  # name -> returned expression
    errors: list[str] = field(default_factory=list)


def tokenize(text: str) -> list[Tok]:
    out: list[Tok] = []
    line = 1
    for m in TOKEN.finditer(text):
        kind = m.lastgroup
        if kind is not None:
            out.append(Tok(kind, m.group(), line))
        line += m.group().count("\n")
    return out


class _Parser:
    def __init__(self, toks: list[Tok]) -> None:
        self.t = toks
        self.i = 0
        self.rs = Ruleset()

    def peek(self, k: int = 0) -> Tok | None:
        j = self.i + k
        return self.t[j] if j < len(self.t) else None

    def next(self) -> Tok:
        tok = self.t[self.i]
        self.i += 1
        return tok

    def until(self, stops: set[str]) -> tuple[str, Tok | None]:
        """Raw text up to a stop punctuation at nesting depth 0 (parens/braces balanced)."""
        depth = 0
        parts: list[str] = []
        while (tok := self.peek()) is not None:
            if tok.kind == "punct" and depth == 0 and tok.text in stops:
                return " ".join(parts), tok
            if tok.text in "({":
                depth += 1
            elif tok.text in ")}":
                depth -= 1
            parts.append(tok.text)
            self.i += 1
        return " ".join(parts), None

    def block(self, path: str) -> None:
        while (tok := self.peek()) is not None:
            if tok.text == "}":
                self.i += 1
                return
            if tok.text == "match":
                self.i += 1
                seg, brace = self.until({"{"})
                self.i += 1 if brace else 0
                self.block(path.rstrip("/") + "/" + seg.replace(" ", "").lstrip("/"))
            elif tok.text == "allow":
                self.i += 1
                ops_text, stop = self.until({":", ";"})
                cond: str | None = None
                if stop is not None and stop.text == ":":
                    self.i += 1
                    cond, stop = self.until({";", "}"})
                    cond = re.sub(r"^if\s+", "", cond.strip())
                if stop is not None and stop.text == ";":
                    self.i += 1
                ops = [o.strip() for o in ops_text.replace(" ", "").split(",") if o.strip()]
                self.rs.allows.append(Allow(path or "/", ops, _norm(cond), tok.line))
            elif tok.text == "function":
                self.i += 1
                name = self.next().text.split("(")[0]
                self.until({"{"})
                self.i += 1
                body, _ = self.until({"}"})
                self.i += 1
                m = re.search(r"\breturn\s+(.*?)\s*;?\s*$", body, re.S)
                if m:
                    self.rs.functions[name] = _norm(m.group(1)) or ""
            elif tok.text == "service":
                self.i += 1
                self.rs.service, _ = self.until({"{"})
                self.i += 1
                self.block("")
            else:
                self.i += 1  # rules_version = '2'; and anything we do not model


def _norm(cond: str | None) -> str | None:
    if cond is None:
        return None
    c = re.sub(r"\s+", " ", cond).strip()
    c = re.sub(r"\s*([().,<>!=&|])\s*", r"\1", c)
    c = c.replace("!=", " != ").replace("<", " < ").replace("==", " == ")
    return re.sub(r"\s+", " ", c).strip()


def parse_rules(text: str) -> Ruleset:
    p = _Parser(tokenize(text))
    try:
        p.block("")
    except IndexError:
        p.rs.errors.append("unexpected end of rules file")
    return p.rs


def _classify(cond: str | None, functions: dict[str, str]) -> str | None:
    if cond is None or cond == "true" or TIME_BOMB.match(cond.replace(" ", " ")):
        return "firebase_open"
    c = cond
    m = re.fullmatch(r"(\w+)\(\)", c)
    if m and m.group(1) in functions:  # isSignedIn() -> request.auth != null
        c = functions[m.group(1)]
        if c == "true":
            return "firebase_open"
    if AUTH_ONLY.match(c.replace(" ", "")) or AUTH_ONLY.match(c):
        return "firebase_auth_only"
    return None


def analyze_rules_file(path: str, text: str) -> list[DataExposure]:
    rs = parse_rules(text)
    kind = "storage" if "storage" in rs.service else "firestore"
    out: list[DataExposure] = []
    for a in rs.allows:
        reason = _classify(a.condition, rs.functions)
        if reason is None:
            continue
        out.append(
            DataExposure(
                resource=f"{kind}:{a.path}",
                role="anon" if reason == "firebase_open" else "authenticated",
                ops=set(a.ops),
                reason=reason,
                loc=Loc(path=path, line=a.line),
                detail=f"allow {', '.join(a.ops)}" + (f": if {a.condition}" if a.condition else ""),
            )
        )
    return out


def analyze_rtdb(path: str, text: str) -> list[DataExposure]:
    try:
        doc = json.loads(text)
    except ValueError:
        return []
    rules = doc.get("rules", doc) if isinstance(doc, dict) else {}
    out: list[DataExposure] = []
    lines = text.splitlines()
    cursor = [0]

    def line_of(key: str) -> int:
        """Keys are visited in document order, so search forward from the last hit."""
        for i in range(cursor[0], len(lines)):
            if f'"{key}"' in lines[i]:
                cursor[0] = i
                return i + 1
        return 1

    def walk(node: object, p: str) -> None:
        if not isinstance(node, dict):
            return
        for k, v in node.items():
            if k in {".read", ".write"}:
                where = line_of(k)
                cond = "true" if v is True else (str(v) if isinstance(v, str) else None)
                if v is False or cond is None:
                    continue
                reason = _classify(_norm(cond), {})
                if reason:
                    op = k[1:]
                    out.append(
                        DataExposure(
                            resource=f"rtdb:{p or '/'}",
                            role="anon" if reason == "firebase_open" else "authenticated",
                            ops={op},
                            reason=reason,
                            loc=Loc(path=path, line=where),
                            detail=f'"{k}": {json.dumps(v)}',
                        )
                    )
            elif not k.startswith("."):
                line_of(k)
                walk(v, f"{p}/{k}")

    walk(rules, "")
    return out


def analyze_firebase(tree: SourceTree) -> list[DataExposure]:
    out: list[DataExposure] = []
    for path in tree.paths():
        if RULE_FILES.search(path):
            out += analyze_rules_file(path, tree.read(path).decode("utf-8", "replace"))
        elif RTDB_FILES.search(path):
            out += analyze_rtdb(path, tree.read(path).decode("utf-8", "replace"))
    return out


def is_write(ops: set[str]) -> bool:
    return bool(ops & WRITE_OPS)
