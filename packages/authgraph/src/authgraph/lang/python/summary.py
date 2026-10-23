"""Per-file summaries (PLAN.md §6.3 step 2). File-local only, so they can be cached by blob SHA."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

ValueKind = Literal["name", "const", "call", "list", "subscript", "fstring", "other"]


class Value(BaseModel):
    """A symbolic expression: enough structure to resolve routers, prefixes and dependencies."""

    kind: ValueKind
    dotted: str | None = None  # name / attribute path, or the callee for kind="call"
    const: str | int | bool | None = None
    args: list[Value] = Field(default_factory=list)
    kwargs: dict[str, Value] = Field(default_factory=dict)
    items: list[Value] = Field(default_factory=list)  # list items / subscript slice elements
    line: int = 0


class Import(BaseModel):
    scope: str  # "" for module level, else function qualname
    module: str  # absolute or relative module ("" for `from . import x`)
    name: str | None  # None for `import a.b`
    asname: str  # local binding
    level: int = 0


class Assign(BaseModel):
    scope: str
    target: str
    value: Value
    line: int
    annotation: Value | None = None


class Param(BaseModel):
    name: str
    annotation: Value | None = None
    default: Value | None = None


class RaiseInfo(BaseModel):
    status: int | None  # HTTP status if recognisable (HTTPException(401), status.HTTP_403_...)
    exc: str
    condition: str | None  # JSON boolean formula of the enclosing if-tests (None = always)
    in_except: bool
    line: int


class ExceptInfo(BaseModel):
    exc: list[str]
    body: Literal["raise", "return", "log_only", "pass", "other"]
    line: int


class SinkInfo(BaseModel):
    kind: Literal["read", "write", "delete"]
    orm: str
    model: str | None
    predicate_names: list[str]  # root names referenced in the filter predicate
    line: int


class MassAssign(BaseModel):
    source: str  # the request-body parameter name that is mass-assigned
    excluded: list[str] = Field(default_factory=list)  # model_dump(exclude={...}) constants
    line: int


class Function(BaseModel):
    qualname: str
    name: str
    line: int
    is_async: bool = False
    params: list[Param] = Field(default_factory=list)
    decorators: list[Value] = Field(default_factory=list)
    returns: Value | None = None
    raises: list[RaiseInfo] = Field(default_factory=list)
    excepts: list[ExceptInfo] = Field(default_factory=list)
    calls: list[str] = Field(default_factory=list)  # dotted callees (helpers that may raise)
    returns_none: bool = False
    return_names: list[str] = Field(default_factory=list)  # `return app` / `return checker`
    return_calls: list[str] = Field(default_factory=list)  # `return make_router(...)` callees
    return_conds: dict[str, str | None] = Field(default_factory=dict)  # name -> path condition
    reads_authorization: bool = False
    token_decode: bool = False
    role_refs: list[str] = Field(default_factory=list)
    owner_compare: bool = False
    sinks: list[SinkInfo] = Field(default_factory=list)
    mass_assign: list[MassAssign] = Field(default_factory=list)
    return_depends: list[Value] = Field(default_factory=list)  # `return Depends(<expr>)` args
    super_init: Value | None = None  # `super().__init__(...)` call (router subclasses)
    first_check_line: int | None = None  # first raise of 401/403 (for dominates_sink)


class ClassInfo(BaseModel):
    name: str
    line: int
    bases: list[str]
    fields: dict[str, Value | None] = Field(default_factory=dict)  # annotated attrs -> default
    methods: list[str] = Field(default_factory=list)  # qualnames of methods (in functions)


class MethodCall(BaseModel):
    """Statement-level ``receiver.method(...)``: include_router, mount, add_api_route, ..."""

    scope: str
    receiver: str
    method: str
    args: list[Value]
    kwargs: dict[str, Value]
    line: int


class FileSummary(BaseModel):
    path: str
    module: str
    blob_sha: str
    is_package: bool = False
    parse_error: str | None = None
    imports: list[Import] = Field(default_factory=list)
    assigns: list[Assign] = Field(default_factory=list)
    functions: dict[str, Function] = Field(default_factory=dict)
    classes: dict[str, ClassInfo] = Field(default_factory=dict)
    method_calls: list[MethodCall] = Field(default_factory=list)
