import json
from pathlib import Path

import pytest
from authgraph.api import diff_trees
from authgraph.diff.logic import weakened
from authgraph.workspace.tree import DirectoryTree

from .helpers import DEPS, write_tree


def F(x: object) -> str:
    return json.dumps(x)


A, B = ["atom", "a"], ["atom", "b"]


@pytest.mark.parametrize(
    ("base", "head", "expected"),
    [
        (F(["or", A, B]), F(["and", A, B]), True),  # or -> and: rejects fewer requests
        (F(["and", A, B]), F(["or", A, B]), False),  # strengthened
        (F(A), F(A), False),
        (F(["or", A, B]), F(["or", B, A]), False),  # reordered, equivalent
        (F(A), F(["atom", "True"]), False),
        (F(["atom", "True"]), F(A), True),  # unconditional -> conditional
        (None, F(A), None),
    ],
)
def test_weakened(base: str | None, head: str | None, expected: bool | None) -> None:
    assert weakened(base, head) is expected


MAIN = """
from fastapi import FastAPI, Depends
from deps import get_current_user, require_admin
app = FastAPI()
@app.get("/items")
def items(user=Depends(get_current_user)): ...
@app.delete("/admin/users/{uid}")
def delete_user(uid: int, admin=Depends(require_admin)): ...
"""


def _diff(tmp_path: Path, base: dict[str, str], head: dict[str, str]) -> list[tuple[str, str]]:
    b = write_tree(tmp_path / "base", base)
    h = write_tree(tmp_path / "head", head)
    r = diff_trees(DirectoryTree(b), DirectoryTree(h), repo_id="r")
    return [(f.rule_id, f.endpoint_id or f.resource or "") for f in r.findings]


def test_new_public_get_in_public_router_is_not_reported(tmp_path: Path) -> None:
    pub = "from fastapi import APIRouter\npublic = APIRouter()\n@public.get('/health')\ndef h(): ...\n"
    base_main = MAIN + "from pub import public\napp.include_router(public)\n"
    found = _diff(
        tmp_path,
        {"deps.py": DEPS, "main.py": base_main, "pub.py": pub},
        {
            "deps.py": DEPS,
            "main.py": base_main,
            "pub.py": pub + "@public.get('/blog')\ndef b(): ...\n",
        },
    )
    assert found == []


def test_new_unauth_get_next_to_authenticated_peers_is_reported(tmp_path: Path) -> None:
    head_main = MAIN + '@app.get("/blog")\ndef blog(): ...\n'
    assert _diff(
        tmp_path, {"deps.py": DEPS, "main.py": MAIN}, {"deps.py": DEPS, "main.py": head_main}
    ) == [("AG-AUTH-001", "GET /blog")]


def test_new_mutating_unauth_route_is_reported(tmp_path: Path) -> None:
    head_main = MAIN + '@app.post("/items")\ndef create(): ...\n'
    assert _diff(
        tmp_path, {"deps.py": DEPS, "main.py": MAIN}, {"deps.py": DEPS, "main.py": head_main}
    ) == [("AG-AUTH-001", "POST /items")]


def test_new_login_route_is_unauthenticated_by_design(tmp_path: Path) -> None:
    head_main = MAIN + '@app.post("/auth/login")\ndef login(): ...\n'
    assert (
        _diff(tmp_path, {"deps.py": DEPS, "main.py": MAIN}, {"deps.py": DEPS, "main.py": head_main})
        == []
    )


@pytest.mark.parametrize(
    ("method", "path", "handler", "reported"),
    [
        ("POST", "/auth/delete-account", "remove", True),
        ("POST", "/public/items", "create", True),
        ("POST", "/token/{id}/delete", "remove", True),
        ("POST", "/items/{token}", "create", True),
        ("POST", "/admin/login", "login", True),
        ("POST", "/admin/users", "create", True),
        ("GET", "/admin/health", "health", True),
        ("POST", "/auth/login", "issue", False),
        ("POST", "/tokens/refresh/", "issue", False),
        ("POST", "/auth/callback/{provider}", "handle", False),
        ("POST", "/{tenant}/webhooks/{hook}", "handle", False),
        ("POST", "/users", "create", False),
    ],
)
def test_new_endpoint_auth_flow_boundaries(
    tmp_path: Path, method: str, path: str, handler: str, reported: bool
) -> None:
    base = "from fastapi import FastAPI\napp = FastAPI()\n"
    head = base + f'@app.{method.lower()}("{path}")\ndef {handler}(): ...\n'
    found = _diff(tmp_path, {"main.py": base}, {"main.py": head})
    assert found == ([("AG-AUTH-001", f"{method} {path.rstrip('/')}")] if reported else [])


@pytest.mark.parametrize("path", ["/auth/items", "/public/items", "/health", "/token/{id}"])
def test_auth_flow_path_does_not_hide_guard_removal(tmp_path: Path, path: str) -> None:
    base = (
        "from fastapi import FastAPI, Depends\nfrom deps import get_current_user\n"
        f'app = FastAPI()\n@app.post("{path}")\ndef manage(user=Depends(get_current_user)): ...\n'
    )
    head = base.replace("user=Depends(get_current_user)", "")
    assert _diff(
        tmp_path, {"deps.py": DEPS, "main.py": base}, {"deps.py": DEPS, "main.py": head}
    ) == [("AG-AUTH-002", f"POST {path}")]


def test_replacing_guard_with_equivalent_guard_is_not_a_removal(tmp_path: Path) -> None:
    deps2 = DEPS + "\ndef get_active_user(user=Depends(get_current_user)):\n    return user\n"
    head_main = MAIN.replace("user=Depends(get_current_user)", "user=Depends(get_active_user)")
    head_main = head_main.replace("import get_current_user,", "import get_active_user,")
    assert (
        _diff(
            tmp_path, {"deps.py": deps2, "main.py": MAIN}, {"deps.py": deps2, "main.py": head_main}
        )
        == []
    )


def test_role_guard_downgraded_to_authn_is_removal(tmp_path: Path) -> None:
    head_main = MAIN.replace("admin=Depends(require_admin)", "admin=Depends(get_current_user)")
    assert _diff(
        tmp_path, {"deps.py": DEPS, "main.py": MAIN}, {"deps.py": DEPS, "main.py": head_main}
    ) == [("AG-AUTH-002", "DELETE /admin/users/{uid}")]


def test_base_config_applies_and_head_config_only_reported(tmp_path: Path) -> None:
    head_main = MAIN + '@app.post("/hooks/x")\ndef hook(): ...\n'
    base_cfg = 'public_routes:\n  - route: "POST /hooks/*"\n'
    found = _diff(
        tmp_path,
        {"deps.py": DEPS, "main.py": MAIN, ".accessguard.yml": base_cfg},
        {"deps.py": DEPS, "main.py": head_main, ".accessguard.yml": base_cfg},
    )
    assert found == []
    # A PR cannot allowlist its own new route: the head config is not applied.
    head_cfg = 'public_routes:\n  - route: "POST /new"\n'
    found = _diff(
        tmp_path / "2",
        {"deps.py": DEPS, "main.py": MAIN},
        {
            "deps.py": DEPS,
            "main.py": MAIN + '@app.post("/new")\ndef n(): ...\n',
            ".accessguard.yml": head_cfg,
        },
    )
    assert sorted(found) == [("AG-AUTH-001", "POST /new"), ("AG-CFG-001", "POST /new")]


def test_fingerprints_stable_when_code_moves_lines(tmp_path: Path) -> None:
    head1 = MAIN.replace("admin=Depends(require_admin)", "")
    head2 = "\n\n\n# moved\n" + head1
    b = write_tree(tmp_path / "b", {"deps.py": DEPS, "main.py": MAIN})
    h1 = write_tree(tmp_path / "h1", {"deps.py": DEPS, "main.py": head1})
    h2 = write_tree(tmp_path / "h2", {"deps.py": DEPS, "main.py": head2})
    f1 = diff_trees(DirectoryTree(b), DirectoryTree(h1), repo_id="r").findings
    f2 = diff_trees(DirectoryTree(b), DirectoryTree(h2), repo_id="r").findings
    assert [f.fingerprint for f in f1] == [f.fingerprint for f in f2] and f1
    assert f1[0].loc.line != f2[0].loc.line


def test_rules_can_be_disabled_by_base_config(tmp_path: Path) -> None:
    head_main = MAIN + '@app.post("/items")\ndef create(): ...\n'
    cfg = "rules:\n  AG-AUTH-001: {enabled: false}\n"
    assert (
        _diff(
            tmp_path,
            {"deps.py": DEPS, "main.py": MAIN, ".accessguard.yml": cfg},
            {"deps.py": DEPS, "main.py": head_main},
        )
        == []
    )


def test_fastapi_users_superuser_to_active_is_a_downgrade(tmp_path: Path) -> None:
    base = """
from fastapi import FastAPI, Depends
from fastapi_users import FastAPIUsers
users = FastAPIUsers(get_user_manager, [backend])
app = FastAPI()
@app.delete("/admin/users/{uid}")
def delete_user(uid: int, u=Depends(users.current_user(active=True, superuser=True))): ...
"""
    head = base.replace("active=True, superuser=True", "active=True")
    assert _diff(tmp_path, {"main.py": base}, {"main.py": head}) == [
        ("AG-AUTH-002", "DELETE /admin/users/{uid}")
    ]


def test_rewritten_guard_with_disjoint_predicates_is_not_weakened() -> None:
    assert (
        weakened(F(["not", ["atom", "u['admin']"]]), F(["not", ["atom", "u.get('admin')"]])) is None
    )


def test_adding_owner_check_to_role_checked_handler_is_not_a_removal(tmp_path: Path) -> None:
    base = """
from fastapi import FastAPI, HTTPException, Depends
from deps import get_current_user
app = FastAPI()
@app.put("/users/{user_id}")
def update_user(user_id: int, body: dict, current_user=Depends(get_current_user)):
    if body.get("role") and current_user.role != "owner":
        raise HTTPException(status_code=403)
"""
    head = base.replace(
        "    if body.get",
        '    if current_user.role != "owner" and current_user.id != user_id:\n'
        "        raise HTTPException(status_code=403)\n    if body.get",
    )
    assert (
        _diff(tmp_path, {"deps.py": DEPS, "main.py": base}, {"deps.py": DEPS, "main.py": head})
        == []
    )


NEUTER_DEPS = """
import logging
from fastapi import Depends, Header, HTTPException
logger = logging.getLogger(__name__)

def get_current_user(authorization: str = Header(...)):
    try:
        claims = decode(authorization)
    except ValueError:
        raise HTTPException(status_code=401)
    return {"id": claims["sub"], "role": claims.get("role", "user")}

def require_admin(user=Depends(get_current_user)):
    if user["role"] != "admin":
        raise HTTPException(status_code=403)
    return user
"""


def test_neutered_authn_is_not_reported_where_a_role_check_still_rejects(tmp_path: Path) -> None:
    # The fallback principal still has to pass require_admin's 403, so only /items opens up.
    head = NEUTER_DEPS.replace(
        "        raise HTTPException(status_code=401)",
        "        logger.warning('invalid token')\n        claims = {'sub': 0}",
    )
    assert _diff(
        tmp_path, {"deps.py": NEUTER_DEPS, "main.py": MAIN}, {"deps.py": head, "main.py": MAIN}
    ) == [("AG-AUTH-002", "GET /items")]
