"""Z3 implication helper for ``condition_weakened`` (FR-3.5; PLAN.md §6.4 diff table).

A guard's predicate is the condition under which it *rejects* the request. The head predicate is
weaker when it rejects strictly fewer requests: ``head => base`` is valid and ``base => head`` is
not. Atoms are compared by their normalized source text, so renamed variables are new atoms.
"""

from __future__ import annotations

import json
from typing import Any

import z3


def _to_z3(f: Any, atoms: dict[str, Any]) -> Any:
    op = f[0]
    if op == "atom":
        text = f[1]
        if text == "True":
            return z3.BoolVal(True)
        if text == "False":
            return z3.BoolVal(False)
        if text not in atoms:
            atoms[text] = z3.Bool(f"a{len(atoms)}")
        return atoms[text]
    if op == "not":
        return z3.Not(_to_z3(f[1], atoms))
    args = [_to_z3(a, atoms) for a in f[1:]]
    return z3.And(*args) if op == "and" else z3.Or(*args)


def _valid(expr: Any) -> bool:
    s = z3.Solver()
    s.set("timeout", 2000)
    s.add(z3.Not(expr))
    return bool(s.check() == z3.unsat)


def weakened(base: str | None, head: str | None) -> bool | None:
    """True if the head rejection predicate is strictly weaker; None if undecidable/absent."""
    if base is None or head is None or base == head:
        return None if base is None or head is None else False
    atoms: dict[str, Any] = {}
    try:
        b = _to_z3(json.loads(base), atoms)
        h = _to_z3(json.loads(head), atoms)
    except (ValueError, IndexError, TypeError, z3.Z3Exception):
        return None
    return _valid(z3.Implies(h, b)) and not _valid(z3.Implies(b, h))


def equivalent(base: str, head: str) -> bool:
    atoms: dict[str, Any] = {}
    b = _to_z3(json.loads(base), atoms)
    h = _to_z3(json.loads(head), atoms)
    return _valid(b == h)
