"""Regenerates eval/mutations/m*_* FastAPI fixtures. Usage: python eval/tools/gen_mutations.py eval/mutations"""

import json
import shutil
import sys
import textwrap
from pathlib import Path

OUT = Path(sys.argv[1])


def d(s: str) -> str:
    return textwrap.dedent(s).lstrip("\n")


BASE = {
    "app/__init__.py": "",
    "app/routers/__init__.py": "",
    "app/models.py": d("""
        from sqlalchemy import Column, Integer, String
        from sqlalchemy.orm import declarative_base

        Base = declarative_base()


        class User(Base):
            __tablename__ = "users"
            id = Column(Integer, primary_key=True)
            name = Column(String)
            role = Column(String, default="user")
            is_active = Column(Integer, default=1)


        class Item(Base):
            __tablename__ = "items"
            id = Column(Integer, primary_key=True)
            title = Column(String)
            owner_id = Column(Integer)
    """),
    "app/db.py": d("""
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker

        SessionLocal = sessionmaker(bind=create_engine("sqlite://"))


        def get_db():
            db = SessionLocal()
            try:
                yield db
            finally:
                db.close()
    """),
    "app/deps.py": d("""
        import logging

        import jwt
        from fastapi import Depends, Header, HTTPException

        from app.models import User

        logger = logging.getLogger(__name__)
        SECRET = "change-me"


        def get_current_user(authorization: str = Header(...)) -> User:
            token = authorization.removeprefix("Bearer ")
            try:
                payload = jwt.decode(token, SECRET, algorithms=["HS256"])
            except jwt.PyJWTError:
                raise HTTPException(status_code=401, detail="invalid token")
            return User(id=int(payload["sub"]), role=payload.get("role", "user"), is_active=1)


        def require_admin(user: User = Depends(get_current_user)) -> User:
            if user.role != "admin" or not user.is_active:
                raise HTTPException(status_code=403, detail="admin only")
            return user
    """),
    "app/main.py": d("""
        from fastapi import Depends, FastAPI

        from app.deps import get_current_user
        from app.routers import admin, items, public, users

        app = FastAPI(title="Example")
        app.include_router(public.router)
        app.include_router(items.router, prefix="/items", dependencies=[Depends(get_current_user)])
        app.include_router(users.router, prefix="/users", dependencies=[Depends(get_current_user)])
        app.include_router(admin.router, prefix="/admin")
    """),
    "app/routers/public.py": d("""
        from fastapi import APIRouter

        router = APIRouter()


        @router.get("/health")
        def health():
            return {"ok": True}
    """),
    "app/routers/items.py": d("""
        from fastapi import APIRouter, Depends

        from app.db import get_db
        from app.deps import get_current_user
        from app.models import Item, User

        router = APIRouter()


        @router.get("/")
        def list_items(db=Depends(get_db)):
            return db.query(Item).all()


        @router.get("/{item_id}")
        def read_item(item_id: int, user: User = Depends(get_current_user), db=Depends(get_db)):
            return db.query(Item).filter(Item.id == item_id, Item.owner_id == user.id).first()
    """),
    "app/routers/users.py": d("""
        from fastapi import APIRouter, Depends
        from pydantic import BaseModel

        from app.db import get_db
        from app.deps import get_current_user
        from app.models import User

        router = APIRouter()


        class UserUpdate(BaseModel):
            name: str | None = None


        @router.patch("/me")
        def update_me(body: UserUpdate, user: User = Depends(get_current_user), db=Depends(get_db)):
            for key, value in body.model_dump(exclude_unset=True).items():
                setattr(user, key, value)
            db.commit()
            return user
    """),
    "app/routers/admin.py": d("""
        from fastapi import APIRouter, Depends

        from app.db import get_db
        from app.deps import require_admin
        from app.models import User

        router = APIRouter()


        @router.delete("/users/{user_id}")
        def delete_user(user_id: int, admin: User = Depends(require_admin), db=Depends(get_db)):
            db.query(User).filter(User.id == user_id).delete()
            db.commit()
    """),
}

CASES: list[dict] = []


def case(cid, kind, desc, edits, expected, base_extra=None, base_override=None):
    CASES.append(
        dict(
            id=cid,
            kind=kind,
            desc=desc,
            edits=edits,
            expected=expected,
            base_extra=base_extra or {},
            base_override=base_override,
        )
    )


def replace(path, old, new):
    return ("replace", path, old, new)


def write(path, content):
    return ("write", path, content)


def delete(path):
    return ("delete", path)


case(
    "m01_new_unauth_mutating_route",
    "positive",
    "Adds an admin action to a router that has no router-level guard and forgets require_admin.",
    [
        replace(
            "app/routers/admin.py",
            "            db.commit()\n" if False else "    db.commit()\n",
            '    db.commit()\n\n\n@router.post("/users/{user_id}/ban")\n'
            "def ban_user(user_id: int, db=Depends(get_db)):\n"
            '    db.query(User).filter(User.id == user_id).update({"is_active": 0})\n'
            "    db.commit()\n",
        )
    ],
    [("AG-AUTH-001", "POST /admin/users/{user_id}/ban")],
)

case(
    "m02_new_route_under_auth_router",
    "negative",
    "Adds a route under the items router, which inherits get_current_user from include_router.",
    [
        replace(
            "app/routers/items.py",
            "    return db.query(Item).filter(Item.id == item_id, Item.owner_id == user.id).first()\n",
            "    return db.query(Item).filter(Item.id == item_id, Item.owner_id == user.id).first()\n\n\n"
            '@router.delete("/{item_id}")\n'
            "def delete_item(item_id: int, user: User = Depends(get_current_user), db=Depends(get_db)):\n"
            "    db.query(Item).filter(Item.id == item_id, Item.owner_id == user.id).delete()\n"
            "    db.commit()\n",
        )
    ],
    [],
)

case(
    "m03_drop_depends",
    "positive",
    "Removes the require_admin dependency from an admin delete endpoint.",
    [
        replace(
            "app/routers/admin.py",
            "def delete_user(user_id: int, admin: User = Depends(require_admin), db=Depends(get_db)):",
            "def delete_user(user_id: int, db=Depends(get_db)):",
        ),
        replace("app/routers/admin.py", "from app.deps import require_admin\n", ""),
    ],
    [("AG-AUTH-002", "DELETE /admin/users/{user_id}")],
)

case(
    "m04_drop_include_dependencies",
    "positive",
    "Removes dependencies= from include_router; list_items loses its only guard, read_item keeps its own.",
    [
        replace(
            "app/main.py",
            'app.include_router(items.router, prefix="/items", dependencies=[Depends(get_current_user)])',
            'app.include_router(items.router, prefix="/items")',
        )
    ],
    [("AG-AUTH-002", "GET /items/")],
)

case(
    "m05_owner_filter_dropped",
    "positive",
    "Drops the owner_id predicate from an item lookup (IDOR regression).",
    [
        replace(
            "app/routers/items.py",
            "filter(Item.id == item_id, Item.owner_id == user.id)",
            "filter(Item.id == item_id)",
        )
    ],
    [("AG-AUTH-002", "GET /items/{item_id}")],
)

case(
    "m06_and_or_weakened",
    "positive",
    "Flips `or` to `and` in require_admin, so any active user passes the admin check.",
    [
        replace(
            "app/deps.py",
            'if user.role != "admin" or not user.is_active:',
            'if user.role != "admin" and not user.is_active:',
        )
    ],
    [("AG-AUTH-002", "DELETE /admin/users/{user_id}")],
)

case(
    "m07_raise_neutered",
    "positive",
    "Replaces the 401 raise with a log line, so invalid tokens fall through.",
    [
        replace(
            "app/deps.py",
            '        raise HTTPException(status_code=401, detail="invalid token")',
            '        logger.warning("invalid token")\n        payload = {"sub": 0}',
        )
    ],
    [
        ("AG-AUTH-002", "GET /items/"),
        ("AG-AUTH-002", "GET /items/{item_id}"),
        ("AG-AUTH-002", "PATCH /users/me"),
    ],
)

case(
    "m08_role_in_update_schema",
    "positive",
    "Adds `role` to a self-update schema that is mass-assigned onto the user.",
    [
        replace(
            "app/routers/users.py",
            "    name: str | None = None\n",
            "    name: str | None = None\n    role: str | None = None\n",
        )
    ],
    [("AG-ROLE-002", "PATCH /users/me")],
)

case(
    "m09_pure_move",
    "move",
    "Moves delete_user into its own module with identical guards; must produce zero findings.",
    [
        write(
            "app/routers/admin.py",
            d("""
        from fastapi import APIRouter

        from app.routers import admin_users

        router = APIRouter()
        router.include_router(admin_users.router)
     """),
        ),
        write("app/routers/admin_users.py", BASE["app/routers/admin.py"]),
    ],
    [],
)

case(
    "m10_public_by_config",
    "negative",
    "Adds GET /status, which the base-branch config already declares public.",
    [
        replace(
            "app/routers/public.py",
            '    return {"ok": True}\n',
            '    return {"ok": True}\n\n\n@router.get("/status")\ndef status():\n    return {"version": "1"}\n',
        )
    ],
    [],
    base_extra={
        ".accessguard.yml": d("""
        version: 1
        public_routes:
          - route: "GET /health"
            reason: liveness probe
          - route: "GET /status"
            reason: version probe
     """)
    },
)

case(
    "m11_config_widened",
    "positive",
    "PR edits .accessguard.yml to declare an admin delete endpoint public.",
    [
        write(
            ".accessguard.yml",
            d("""
        version: 1
        public_routes:
          - route: "GET /health"
            reason: liveness probe
          - route: "DELETE /admin/users/{user_id}"
            reason: temporary
     """),
        )
    ],
    [("AG-CFG-001", "DELETE /admin/users/{user_id}")],
    base_extra={
        ".accessguard.yml": d("""
        version: 1
        public_routes:
          - route: "GET /health"
            reason: liveness probe
     """)
    },
)

MOUNT_BASE = {
    "app/__init__.py": "",
    "app/deps.py": BASE["app/deps.py"],
    "app/models.py": BASE["app/models.py"],
    "app/main.py": d("""
        from fastapi import Depends, FastAPI

        from app.deps import get_current_user

        app = FastAPI(dependencies=[Depends(get_current_user)])


        @app.get("/reports")
        def reports():
            return []
    """),
}
case(
    "m12_mount_subapp_without_auth",
    "positive",
    "Mounts a sub-application; mounted apps do not inherit the parent app's dependencies.",
    [
        replace(
            "app/main.py",
            '@app.get("/reports")',
            'internal = FastAPI()\n\n\n@internal.post("/reindex")\ndef reindex():\n    return {"queued": True}\n\n\n'
            'app.mount("/internal", internal)\n\n\n@app.get("/reports")',
        )
    ],
    [("AG-AUTH-003", "POST /internal/reindex")],
    base_override=MOUNT_BASE,
)

# --- Phase 1 additions: a negative for every rule, more positive shapes ----------------------
case(
    "m13_equivalent_guard_swap",
    "negative",
    "Replaces get_current_user with get_active_user, which itself depends on get_current_user.",
    [
        replace(
            "app/deps.py",
            "def require_admin(",
            "def get_active_user(user: User = Depends(get_current_user)) -> User:\n    return user\n\n\ndef require_admin(",
        ),
        replace(
            "app/routers/users.py",
            "from app.deps import get_current_user",
            "from app.deps import get_active_user",
        ),
        replace("app/routers/users.py", "Depends(get_current_user)", "Depends(get_active_user)"),
    ],
    [],
)
case(
    "m14_guard_moved_include_to_router",
    "negative",
    "Moves the items guard from include_router(dependencies=) to APIRouter(dependencies=).",
    [
        replace(
            "app/main.py",
            'app.include_router(items.router, prefix="/items", dependencies=[Depends(get_current_user)])',
            'app.include_router(items.router, prefix="/items")',
        ),
        replace(
            "app/routers/items.py",
            "router = APIRouter()",
            "router = APIRouter(dependencies=[Depends(get_current_user)])",
        ),
    ],
    [],
)
NOTES = d("""
    from fastapi import APIRouter, Depends, HTTPException

    from app.db import get_db
    from app.deps import get_current_user
    from app.models import Item, User

    router = APIRouter()


    @router.delete("/{item_id}")
    def delete_note(item_id: int, user: User = Depends(get_current_user), db=Depends(get_db)):
        item = db.query(Item).filter(Item.id == item_id).first()
        if item.owner_id != user.id:
            raise HTTPException(status_code=403, detail="not yours")
        db.query(Item).filter(Item.id == item_id).delete()
        db.commit()
""")
NOTES_CHECK = (
    "    if item.owner_id != user.id:\n"
    '        raise HTTPException(status_code=403, detail="not yours")\n'
)
NOTES_DELETE = "    db.query(Item).filter(Item.id == item_id).delete()\n    db.commit()\n"
NOTES_MAIN = (
    BASE["app/main.py"].replace(
        "from app.routers import admin, items, public, users",
        "from app.routers import admin, items, notes, public, users",
    )
    + 'app.include_router(notes.router, prefix="/notes")\n'
)
case(
    "m15_check_moved_after_delete",
    "positive",
    "Moves the ownership check below the delete, so any user can delete any note.",
    [
        write(
            "app/routers/notes.py",
            NOTES.replace(NOTES_CHECK + NOTES_DELETE, NOTES_DELETE + NOTES_CHECK),
        )
    ],
    [("AG-AUTH-002", "DELETE /notes/{item_id}")],
    base_extra={"app/routers/notes.py": NOTES, "app/main.py": NOTES_MAIN},
)
case(
    "m16_condition_strengthened",
    "negative",
    "Adds a third rejection clause to require_admin (stricter, not weaker).",
    [
        replace(
            "app/deps.py",
            'if user.role != "admin" or not user.is_active:',
            'if user.role != "admin" or not user.is_active or user.id == 0:',
        )
    ],
    [],
)
case(
    "m17_role_field_on_admin_endpoint",
    "negative",
    "Admins may set roles: role in a body mass-assigned behind require_admin is not AG-ROLE-002.",
    [
        replace(
            "app/routers/admin.py",
            "from fastapi import APIRouter, Depends",
            "from fastapi import APIRouter, Depends\nfrom pydantic import BaseModel",
        ),
        replace(
            "app/routers/admin.py",
            "router = APIRouter()\n",
            "router = APIRouter()\n\n\nclass AdminUserUpdate(BaseModel):\n    role: str | None = None\n\n\n"
            '@router.patch("/users/{user_id}")\n'
            "def admin_update(user_id: int, body: AdminUserUpdate, admin: User = Depends(require_admin), db=Depends(get_db)):\n"
            "    user = db.query(User).filter(User.id == user_id).first()\n"
            "    for key, value in body.model_dump(exclude_unset=True).items():\n"
            "        setattr(user, key, value)\n"
            "    db.commit()\n",
        ),
    ],
    [],
)
case(
    "m18_mount_with_own_auth",
    "negative",
    "Mounts a sub-application that declares its own auth dependency.",
    [
        replace(
            "app/main.py",
            '@app.get("/reports")',
            'internal = FastAPI(dependencies=[Depends(get_current_user)])\n\n\n@internal.post("/reindex")\n'
            'def reindex():\n    return {"queued": True}\n\n\n'
            'app.mount("/internal", internal)\n\n\n@app.get("/reports")',
        )
    ],
    [],
    base_override=MOUNT_BASE,
)
CFG = 'version: 1\npublic_routes:\n  - route: "GET /health"\n    reason: liveness probe\n'
case(
    "m19_config_narrowed",
    "negative",
    "PR removes a public route from .accessguard.yml (narrowing is never reported).",
    [write(".accessguard.yml", "version: 1\npublic_routes: []\n")],
    [],
    base_extra={".accessguard.yml": CFG},
)
case(
    "m20_add_api_route_unauth",
    "positive",
    "Registers a new admin action with add_api_route and no guard.",
    [
        replace(
            "app/routers/admin.py",
            "router = APIRouter()\n",
            "router = APIRouter()\n\n\ndef promote(user_id: int, db=Depends(get_db)):\n"
            '    db.query(User).filter(User.id == user_id).update({"role": "admin"})\n\n\n'
            'router.add_api_route("/users/{user_id}/promote", promote, methods=["POST"])\n',
        )
    ],
    [("AG-AUTH-001", "POST /admin/users/{user_id}/promote")],
)
case(
    "m21_guard_moved_to_new_module",
    "move",
    "Moves get_current_user into app/security.py and imports it from there in app/deps.py.",
    [
        write(
            "app/security.py", BASE["app/deps.py"].split("def require_admin(")[0].rstrip() + "\n"
        ),
        write(
            "app/deps.py",
            "from fastapi import Depends, HTTPException\n\nfrom app.models import User\n"
            "from app.security import get_current_user\n\n\n"
            "def require_admin(" + BASE["app/deps.py"].split("def require_admin(")[1],
        ),
    ],
    [],
)
case(
    "m22_admin_branch_added_owner_filter_kept",
    "negative",
    "Adds an unscoped admin branch next to the still-scoped user query (multiset compare).",
    [
        replace(
            "app/routers/items.py",
            "    return db.query(Item).filter(Item.id == item_id, Item.owner_id == user.id).first()",
            '    if user.role == "admin":\n        return db.query(Item).filter(Item.id == item_id).first()\n'
            "    return db.query(Item).filter(Item.id == item_id, Item.owner_id == user.id).first()",
        )
    ],
    [],
)


def materialize(root: Path, files: dict[str, str]) -> None:
    for rel, content in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8", newline="\n")


for c in CASES:
    cdir = OUT / c["id"]
    if cdir.exists():
        shutil.rmtree(cdir)
    base_files = dict(c["base_override"] or BASE)
    base_files.update(c["base_extra"])
    head_files = dict(base_files)
    for e in c["edits"]:
        if e[0] == "replace":
            _, path, old, new = e
            assert head_files[path].count(old) == 1, (c["id"], path, old)
            head_files[path] = head_files[path].replace(old, new)
        elif e[0] == "write":
            head_files[e[1]] = e[2]
        else:
            del head_files[e[1]]
    materialize(cdir / "base", base_files)
    materialize(cdir / "head", head_files)
    lines = [
        f"id: {c['id']}",
        f"kind: {c['kind']}",
        "framework: fastapi",
        f"description: {json.dumps(c['desc'])}",
        "expected:" + ("" if c["expected"] else " []"),
    ]
    for rule, key in c["expected"]:
        lines += [f"  - rule_id: {rule}", f'    key: "{key}"']
    (cdir / "case.yaml").write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    print("wrote", c["id"])
