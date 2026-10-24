"""Per-file JavaScript/TypeScript summary (FR-3.6): facts only, cached by git blob SHA.

A summary is a source-ordered list of *events* (assignments and expression calls) per function,
plus the guard features of each function. The Express graph replays these events abstractly
(``frameworks/express.py``); nothing from the scanned repository is ever executed.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

ValueKind = Literal[
    "str",  # string literal or no-substitution template
    "num",
    "bool",
    "null",
    "id",  # identifier (s = name)
    "member",  # obj.s
    "call",  # obj(args)
    "new",  # new obj(args)
    "func",  # function literal (s = function id)
    "array",  # [args]
    "object",  # {props}
    "regex",  # s = pattern
    "tmpl",  # template literal with substitutions: args = parts (str fragments and expressions)
    "spread",  # ...obj
    "other",  # anything we do not model (s = node type)
]


class _M(BaseModel):
    model_config = ConfigDict(extra="forbid")


class JsValue(_M):
    k: ValueKind
    s: str = ""
    obj: JsValue | None = None
    args: list[JsValue] = Field(default_factory=list)
    props: dict[str, JsValue] = Field(default_factory=dict)
    line: int = 0

    def dotted(self) -> str | None:
        """``a.b.c`` for identifier/member chains, else None."""
        if self.k == "id":
            return self.s
        if self.k == "member" and self.obj is not None:
            base = self.obj.dotted()
            return f"{base}.{self.s}" if base else None
        return None


class JsEvent(_M):
    k: Literal["assign", "expr"]
    name: str = ""  # assignment target: identifier, or dotted (``module.exports.x``)
    value: JsValue
    line: int


class JsFunction(_M):
    id: str  # "<path>#<name>@<line>"
    name: str  # declared or assigned name ("" for anonymous)
    params: list[str] = Field(default_factory=list)  # "" for destructured params
    line: int
    events: list[JsEvent] = Field(default_factory=list)
    returns: list[JsValue] = Field(default_factory=list)
    # Guard features (FR-7.6), collected from the body and inline callbacks in it.
    statuses: list[int] = Field(default_factory=list)  # 4xx the function responds/throws with
    calls: list[str] = Field(default_factory=list)  # dotted callee names
    calls_next: bool = False  # next() with no argument (passes the request on)
    forwards_next: bool = False  # passes `next` on as an argument (delegating middleware)
    next_error: bool = False  # next(err): hands a failure to the error handler
    sends: bool = False  # res.send/json/end/render/redirect: answers the request itself
    role_compare: bool = False  # compares a role/permission attribute
    owner_compare: bool = False  # compares a request id param with the principal's id
    logs: bool = False


class JsImport(_M):
    source: str  # module specifier as written
    name: str  # exported name, "default", or "*" for the namespace / require() value
    line: int


class JsFileSummary(_M):
    path: str
    blob_sha: str
    parse_error: str | None = None
    imports: dict[str, JsImport] = Field(default_factory=dict)  # local name -> import
    # export name -> value; "default" for ``export default`` / ``module.exports =``.
    exports: dict[str, JsValue] = Field(default_factory=dict)
    reexports: list[JsImport] = Field(default_factory=list)  # ``export * from`` (name "*")
    functions: dict[str, JsFunction] = Field(default_factory=dict)
    module_fn: str = ""  # id of the synthetic function holding top-level events
