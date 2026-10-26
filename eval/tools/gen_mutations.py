"""Regenerates eval/mutations/m*_* FastAPI and Express fixtures. Usage: python eval/tools/gen_mutations.py eval/mutations"""

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


def case(
    cid, kind, desc, edits, expected, base_extra=None, base_override=None, framework="fastapi"
):
    CASES.append(
        dict(
            id=cid,
            kind=kind,
            desc=desc,
            edits=edits,
            expected=expected,
            base_extra=base_extra or {},
            base_override=base_override,
            framework=framework,
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


# ---- Express (Phase 3) -----------------------------------------------------------------------
EXPRESS = {
    "package.json": d("""
        {
          "name": "express-fixture",
          "private": true,
          "dependencies": {"express": "^4.21.2", "express-jwt": "^8.5.1"}
        }
    """),
    "src/auth.js": d("""
        const { expressjwt } = require('express-jwt');

        const requireAuth = expressjwt({ secret: process.env.JWT_SECRET, algorithms: ['HS256'] });

        function requireAdmin(req, res, next) {
          if (!req.auth || req.auth.role !== 'admin') {
            return res.status(403).json({ error: 'forbidden' });
          }
          next();
        }

        module.exports = { requireAuth, requireAdmin };
    """),
    "src/routes/items.js": d("""
        const express = require('express');

        const router = express.Router();

        router.get('/', (req, res) => res.json([]));
        router.get('/:id', (req, res) => res.json({ id: req.params.id }));
        router.post('/', (req, res) => res.status(201).json(req.body));
        router.delete('/:id', (req, res) => res.status(204).end());

        module.exports = router;
    """),
    "src/routes/admin.js": d("""
        const express = require('express');
        const { requireAdmin } = require('../auth');

        const router = express.Router();
        router.use(requireAdmin);

        router.get('/users', (req, res) => res.json([]));
        router.delete('/users/:id', (req, res) => res.status(204).end());

        module.exports = router;
    """),
    "src/routes/public.js": d("""
        const express = require('express');

        const router = express.Router();

        router.get('/health', (req, res) => res.json({ ok: true }));
        router.get('/docs', (req, res) => res.send('docs'));

        module.exports = router;
    """),
    "src/routes/reports.js": d("""
        const express = require('express');
        const { requireAuth } = require('../auth');

        const router = express.Router();

        router.get('/', requireAuth, (req, res) => res.json([]));

        module.exports = router;
    """),
    "src/routes/orders.ts": d("""
        import { Request, Response, Router } from 'express';
        import { requireAuth } from '../auth';

        const router = Router();

        function getOrder(req: Request, res: Response) {
          res.json({ id: req.params.id });
        }

        function deleteOrder(req: Request, res: Response) {
          res.status(204).end();
        }

        router.route('/:id').get(requireAuth, getOrder).delete(requireAuth, deleteOrder);

        export default router;
    """),
    "src/app.js": d("""
        const express = require('express');
        const { requireAuth } = require('./auth');
        const items = require('./routes/items');
        const admin = require('./routes/admin');
        const publicRoutes = require('./routes/public');
        const reports = require('./routes/reports');
        const orders = require('./routes/orders').default;

        const app = express();
        app.use(express.json());

        app.use('/public', publicRoutes);
        app.use('/reports', reports);
        app.use('/orders', orders);

        app.use('/api', requireAuth);
        app.use('/api/items', items);
        app.use('/api/admin', admin);

        module.exports = app;
    """),
}
EXPRESS_ITEMS = ["GET /api/items", "GET /api/items/:id", "POST /api/items", "DELETE /api/items/:id"]

case(
    "m23_express_route_before_auth_middleware",
    "positive",
    "Registers POST /api/export on the app before app.use('/api', requireAuth).",
    [
        replace(
            "src/app.js",
            "app.use('/api', requireAuth);\n",
            "app.post('/api/export', (req, res) => res.json({ rows: [] }));\n"
            "app.use('/api', requireAuth);\n",
        )
    ],
    [("AG-AUTH-003", "POST /api/export")],
    base_override=EXPRESS,
    framework="express",
)
case(
    "m24_express_router_mounted_before_auth",
    "positive",
    "Moves the items router mount above the /api auth middleware.",
    [
        replace(
            "src/app.js",
            "app.use('/api', requireAuth);\napp.use('/api/items', items);\n",
            "app.use('/api/items', items);\napp.use('/api', requireAuth);\n",
        )
    ],
    [("AG-AUTH-002", k) for k in EXPRESS_ITEMS],
    base_override=EXPRESS,
    framework="express",
)
case(
    "m25_express_route_guard_removed",
    "positive",
    "Drops requireAuth from the reports route.",
    [replace("src/routes/reports.js", "router.get('/', requireAuth, (req", "router.get('/', (req")],
    [("AG-AUTH-002", "GET /reports")],
    base_override=EXPRESS,
    framework="express",
)
case(
    "m26_express_admin_middleware_removed",
    "positive",
    "Removes router.use(requireAdmin) from the admin router; authentication alone remains.",
    [replace("src/routes/admin.js", "router.use(requireAdmin);\n", "")],
    [("AG-AUTH-002", "GET /api/admin/users"), ("AG-AUTH-002", "DELETE /api/admin/users/:id")],
    base_override=EXPRESS,
    framework="express",
)
case(
    "m27_express_new_public_get",
    "negative",
    "Adds GET /public/version to the public router.",
    [
        replace(
            "src/routes/public.js",
            "module.exports = router;",
            "router.get('/version', (req, res) => res.json({ v: 1 }));\n\nmodule.exports = router;",
        )
    ],
    [],
    base_override=EXPRESS,
    framework="express",
)
case(
    "m28_express_guard_moved_to_router_use",
    "negative",
    "Replaces the per-route requireAuth with router.use(requireAuth): same protection.",
    [
        replace(
            "src/routes/reports.js",
            "router.get('/', requireAuth, (req",
            "router.use(requireAuth);\nrouter.get('/', (req",
        )
    ],
    [],
    base_override=EXPRESS,
    framework="express",
)
case(
    "m29_express_unless_exempts_collection",
    "positive",
    "Exempts /api/items from the JWT middleware with express-unless.",
    [
        replace(
            "src/app.js",
            "app.use('/api', requireAuth);",
            "app.use('/api', requireAuth.unless({ path: ['/api/items'] }));",
        )
    ],
    [("AG-AUTH-002", "GET /api/items"), ("AG-AUTH-002", "POST /api/items")],
    base_override=EXPRESS,
    framework="express",
)
case(
    "m30_express_new_route_behind_auth",
    "negative",
    "Adds POST /api/items/:id/archive inside the authenticated items router.",
    [
        replace(
            "src/routes/items.js",
            "module.exports = router;",
            "router.post('/:id/archive', (req, res) => res.status(202).end());\n\nmodule.exports = router;",
        )
    ],
    [],
    base_override=EXPRESS,
    framework="express",
)
case(
    "m31_express_jwt_made_optional",
    "positive",
    "Sets credentialsRequired: false on the shared JWT middleware; admin routes keep their role "
    "check, every other route that used it opens up.",
    [
        replace(
            "src/auth.js",
            "algorithms: ['HS256'] });",
            "algorithms: ['HS256'], credentialsRequired: false });",
        )
    ],
    [("AG-AUTH-002", k) for k in EXPRESS_ITEMS]
    + [
        ("AG-AUTH-002", "GET /reports"),
        ("AG-AUTH-002", "GET /orders/:id"),
        ("AG-AUTH-002", "DELETE /orders/:id"),
    ],
    base_override=EXPRESS,
    framework="express",
)
case(
    "m32_express_ts_route_chain_guard_removed",
    "positive",
    "TypeScript router.route() chain: drops requireAuth from the DELETE handler only.",
    [replace("src/routes/orders.ts", ".delete(requireAuth, deleteOrder)", ".delete(deleteOrder)")],
    [("AG-AUTH-002", "DELETE /orders/:id")],
    base_override=EXPRESS,
    framework="express",
)


# ---- AG-ROLE-001 role consistency (Phase 3) ---------------------------------------------------
STAFF = {
    "app/routers/staff.py": d("""
        from fastapi import APIRouter, Depends

        from app.deps import get_current_user, require_admin

        router = APIRouter()


        @router.post("/announcements")
        def announce(admin=Depends(require_admin)):
            return {}


        @router.put("/settings")
        def update_settings(admin=Depends(require_admin)):
            return {}


        @router.patch("/quotas")
        def update_quotas(admin=Depends(require_admin)):
            return {}


        @router.delete("/sessions")
        def revoke_sessions(admin=Depends(require_admin)):
            return {}


        @router.get("/stats")
        def stats(user=Depends(get_current_user)):
            return {}
    """),
    "app/main.py": d("""
        from fastapi import Depends, FastAPI

        from app.deps import get_current_user
        from app.routers import admin, items, public, staff, users

        app = FastAPI(title="Example")
        app.include_router(public.router)
        app.include_router(items.router, prefix="/items", dependencies=[Depends(get_current_user)])
        app.include_router(users.router, prefix="/users", dependencies=[Depends(get_current_user)])
        app.include_router(admin.router, prefix="/admin")
        app.include_router(staff.router, prefix="/staff")
    """),
}
STAFF_ROUTE = (
    '\n\n@router.post("/broadcast")\ndef broadcast(user=Depends({dep})):\n    return {{}}\n'
)

case(
    "m33_role_peer_inconsistency",
    "positive",
    "Adds POST /staff/broadcast with authentication only; the four other write routes on the "
    "staff router all require_admin.",
    [("write_append", "app/routers/staff.py", STAFF_ROUTE.format(dep="get_current_user"))],
    [("AG-ROLE-001", "POST /staff/broadcast")],
    base_extra=STAFF,
)
case(
    "m34_role_peer_consistent",
    "negative",
    "Adds POST /staff/broadcast with require_admin, like its peers.",
    [("write_append", "app/routers/staff.py", STAFF_ROUTE.format(dep="require_admin"))],
    [],
    base_extra=STAFF,
)
case(
    "m35_admin_path_write_without_role",
    "positive",
    "Adds POST /admin/broadcast to the admin router with authentication only (absolute rule: "
    "too few peers for statistics).",
    [
        (
            "write_append",
            "app/routers/admin.py",
            '\n\n@router.post("/broadcast")\n'
            "def broadcast(user=Depends(get_current_user)):\n    return {}\n",
        ),
        replace(
            "app/routers/admin.py",
            "from app.deps import require_admin",
            "from app.deps import get_current_user, require_admin",
        ),
    ],
    [("AG-ROLE-001", "POST /admin/broadcast")],
)
case(
    "m36_new_read_on_role_free_router",
    "negative",
    "Adds GET /staff/health next to GET /staff/stats; reads on this router are authentication "
    "only, so there is no role pattern to deviate from.",
    [
        (
            "write_append",
            "app/routers/staff.py",
            '\n\n@router.get("/health")\ndef health(user=Depends(get_current_user)):\n'
            "    return {}\n",
        )
    ],
    [],
    base_extra=STAFF,
)
EXPRESS_STAFF = {
    "src/routes/staff.js": d("""
        const express = require('express');
        const { requireAdmin } = require('../auth');

        const router = express.Router();

        router.post('/announcements', requireAdmin, (req, res) => res.json({}));
        router.put('/settings', requireAdmin, (req, res) => res.json({}));
        router.patch('/quotas', requireAdmin, (req, res) => res.json({}));
        router.delete('/sessions', requireAdmin, (req, res) => res.status(204).end());

        module.exports = router;
    """),
}
case(
    "m37_express_role_peer_inconsistency",
    "positive",
    "Adds POST /api/staff/broadcast without requireAdmin; its four write peers have it.",
    [
        replace(
            "src/routes/staff.js",
            "module.exports = router;",
            "router.post('/broadcast', (req, res) => res.json({}));\n\nmodule.exports = router;",
        ),
    ],
    [("AG-ROLE-001", "POST /api/staff/broadcast")],
    base_override={
        **EXPRESS,
        **EXPRESS_STAFF,
        "src/app.js": EXPRESS["src/app.js"].replace(
            "app.use('/api/admin', admin);\n",
            "app.use('/api/admin', admin);\napp.use('/api/staff', require('./routes/staff'));\n",
        ),
    },
    framework="express",
)


# ---- AG-IDOR-001/002 object-level authorization (Phase 3) ------------------------------------
def items_route(code):
    return ("write_append", "app/routers/items.py", "\n\n" + d(code))


ITEMS_IMPORT = replace(
    "app/routers/items.py",
    "from fastapi import APIRouter, Depends",
    "from fastapi import APIRouter, Depends, HTTPException",
)
case(
    "m38_idor_delete_by_id_no_user",
    "positive",
    "Adds DELETE /items/{item_id} that deletes by id without any reference to the current user "
    "(the router is authenticated, so any user can delete any item).",
    [
        items_route("""
            @router.delete("/{item_id}")
            def delete_item(item_id: int, db=Depends(get_db)):
                db.query(Item).filter(Item.id == item_id).delete()
                db.commit()
        """)
    ],
    [("AG-IDOR-001", "DELETE /items/{item_id}")],
)
case(
    "m39_idor_through_service_function",
    "positive",
    "Adds POST /items/{item_id}/archive whose id reaches the update in a service function.",
    [
        (
            "write",
            "app/services.py",
            d("""
            from app.models import Item


            def archive(db, item_id):
                db.query(Item).filter(Item.id == item_id).update({"title": "archived"})
                db.commit()
        """),
        ),
        items_route("""
            @router.post("/{item_id}/archive")
            def archive_item(item_id: int, db=Depends(get_db)):
                services.archive(db, item_id)
        """),
        replace(
            "app/routers/items.py",
            "from app.db import get_db",
            "from app import services\nfrom app.db import get_db",
        ),
    ],
    [("AG-IDOR-001", "POST /items/{item_id}/archive")],
)
case(
    "m40_idor_scoped_lookup",
    "negative",
    "Adds DELETE /items/{item_id} scoped to the current user in the filter.",
    [
        items_route("""
            @router.delete("/{item_id}")
            def delete_item(item_id: int, user: User = Depends(get_current_user), db=Depends(get_db)):
                db.query(Item).filter(Item.id == item_id, Item.owner_id == user.id).delete()
                db.commit()
        """)
    ],
    [],
)
case(
    "m41_idor_owner_check_after_fetch",
    "negative",
    "Adds PATCH /items/{item_id} that fetches by id and then rejects other users with 403.",
    [
        ITEMS_IMPORT,
        items_route("""
            @router.patch("/{item_id}")
            def rename_item(
                item_id: int, title: str, user: User = Depends(get_current_user), db=Depends(get_db)
            ):
                item = db.query(Item).filter(Item.id == item_id).first()
                if item.owner_id != user.id:
                    raise HTTPException(status_code=403)
                item.title = title
                db.commit()
        """),
    ],
    [],
)
case(
    "m42_idor_user_not_tied_to_object",
    "positive",
    "Adds PUT /items/{item_id} that loads the current user but updates any item by id.",
    [
        items_route("""
            @router.put("/{item_id}")
            def update_item(item_id: int, title: str, user: User = Depends(get_current_user), db=Depends(get_db)):
                db.query(Item).filter(Item.id == item_id).update({"title": title})
                db.commit()
                return {"updated_by": user.id}
        """)
    ],
    [("AG-IDOR-002", "PUT /items/{item_id}")],
)


# ---- Data layer: Supabase, Firebase, client secrets (Phase 3) -------------------------------
def _fake_jwt(role):
    import base64

    def b64(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")

    claims = {"iss": "accessguard-fixture", "ref": "fixture0000000000", "role": role}
    return f"{b64({'alg': 'HS256', 'typ': 'JWT'})}.{b64(claims)}.ZmFrZS1zaWduYXR1cmUtZm9yLWV2YWw"


MIG = "supabase/migrations/20240101000000_init.sql"
MIG2 = "supabase/migrations/20240201000000_change.sql"
DATA = {
    "package.json": d("""
        {"name": "data-fixture", "private": true, "dependencies": {"@supabase/supabase-js": "^2"}}
    """),
    MIG: d("""
        create table public.profiles (id uuid primary key references auth.users, name text);
        alter table public.profiles enable row level security;
        create policy "profiles read own" on public.profiles for select to authenticated
          using ((select auth.uid()) = id);
        create policy "profiles update own" on public.profiles for update to authenticated
          using ((select auth.uid()) = id);

        create table public.posts (id bigint generated always as identity primary key,
          author uuid not null references auth.users, body text);
        alter table public.posts enable row level security;
        create policy "posts are public" on public.posts for select to anon, authenticated
          using (true);
        create policy "posts insert own" on public.posts for insert to authenticated
          with check ((select auth.uid()) = author);

        create view public.post_feed with (security_invoker = true) as
          select id, body from public.posts;
    """),
    "firestore.rules": d("""
        rules_version = '2';
        service cloud.firestore {
          match /databases/{database}/documents {
            function isOwner(uid) { return request.auth != null && request.auth.uid == uid; }
            match /users/{userId} {
              allow read, write: if isOwner(userId);
            }
            match /announcements/{id} {
              allow read: if request.auth != null && request.auth.token.admin == true;
            }
          }
        }
    """),
    "src/lib/supabase.ts": d("""
        import { createClient } from '@supabase/supabase-js';

        export const supabase = createClient(
          process.env.NEXT_PUBLIC_SUPABASE_URL!,
          process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,
        );
    """),
    "src/app/api/admin/route.ts": d("""
        import { createClient } from '@supabase/supabase-js';

        const admin = createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);

        export async function GET() {
          const { data } = await admin.from('profiles').select('*');
          return Response.json(data);
        }
    """),
}


def data_case(cid, kind, desc, edits, expected):
    case(cid, kind, desc, edits, expected, base_override=DATA, framework="data")


data_case(
    "m43_supabase_table_without_rls",
    "positive",
    "A migration creates public.audit_log without enabling row level security.",
    [("write", MIG2, "create table public.audit_log (id bigint, actor uuid, action text);\n")],
    [("AG-DATA-001", "public.audit_log")],
)
data_case(
    "m44_supabase_rls_disabled",
    "positive",
    "A migration disables row level security on public.profiles.",
    [("write", MIG2, "alter table public.profiles disable row level security;\n")],
    [("AG-DATA-001", "public.profiles")],
)
data_case(
    "m45_supabase_new_table_with_owner_policies",
    "negative",
    "A migration adds public.notes with RLS and owner-only policies.",
    [
        (
            "write",
            MIG2,
            d("""
                create table public.notes (id bigint primary key, owner uuid, body text);
                alter table public.notes enable row level security;
                create policy "notes own" on public.notes for all to authenticated
                  using ((select auth.uid()) = owner) with check ((select auth.uid()) = owner);
            """),
        )
    ],
    [],
)
data_case(
    "m46_supabase_update_policy_true",
    "positive",
    "Replaces the owner check of the posts insert policy with true for anon.",
    [
        (
            "write",
            MIG2,
            'create policy "anyone edits posts" on public.posts for update to anon using (true);\n',
        )
    ],
    [("AG-DATA-001", "public.posts")],
)
data_case(
    "m47_supabase_null_fail_open",
    "positive",
    "The profiles update policy also passes rows whose id is NULL.",
    [
        (
            "write",
            MIG2,
            'alter policy "profiles update own" on public.profiles\n'
            "  using ((select auth.uid()) = id or id is null);\n",
        )
    ],
    [("AG-DATA-002", "public.profiles")],
)
data_case(
    "m48_supabase_view_bypasses_rls",
    "positive",
    "Adds a view over public.profiles without security_invoker.",
    [
        (
            "write",
            MIG2,
            "create view public.profile_names as select id, name from public.profiles;\n",
        )
    ],
    [("AG-DATA-001", "public.profile_names")],
)
data_case(
    "m49_supabase_view_security_invoker",
    "negative",
    "Adds the same view with security_invoker = true.",
    [
        (
            "write",
            MIG2,
            "create view public.profile_names with (security_invoker = true) as\n"
            "  select id, name from public.profiles;\n",
        )
    ],
    [],
)
data_case(
    "m50_firebase_rule_opened",
    "positive",
    "Opens the users collection to everyone.",
    [
        replace(
            "firestore.rules",
            "allow read, write: if isOwner(userId);",
            "allow read, write: if true;",
        )
    ],
    [("AG-DATA-003", "firestore.rules:/users/{userId}")],
)
data_case(
    "m51_firebase_new_owner_rule",
    "negative",
    "Adds an owner-checked orders collection.",
    [
        replace(
            "firestore.rules",
            "    match /announcements/{id} {",
            "    match /orders/{orderId} {\n"
            "      allow read, write: if isOwner(resource.data.uid);\n"
            "    }\n    match /announcements/{id} {",
        )
    ],
    [],
)
data_case(
    "m52_firebase_auth_only_write",
    "positive",
    "Lets any signed-in user write announcements.",
    [
        replace(
            "firestore.rules",
            "      allow read: if request.auth != null && request.auth.token.admin == true;",
            "      allow read: if request.auth != null && request.auth.token.admin == true;\n"
            "      allow write: if request.auth != null;",
        )
    ],
    [("AG-DATA-003", "firestore.rules:/announcements/{id}")],
)
data_case(
    "m53_service_role_key_in_client",
    "positive",
    "Hard-codes a service-role JWT in the browser Supabase client.",
    [
        replace(
            "src/lib/supabase.ts",
            "process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,",
            f"'{_fake_jwt('service_role')}',",
        )
    ],
    [("AG-SECRET-001", "src/lib/supabase.ts#supabase_service_role_jwt")],
)
data_case(
    "m54_service_role_key_on_server",
    "negative",
    "Hard-codes the same key in a server route handler (bad practice, but not client exposure).",
    [
        replace(
            "src/app/api/admin/route.ts",
            "process.env.SUPABASE_SERVICE_ROLE_KEY!",
            f"'{_fake_jwt('service_role')}'",
        )
    ],
    [],
)
data_case(
    "m55_secret_env_with_public_prefix",
    "positive",
    "Reads the service-role key from a NEXT_PUBLIC_ variable, which Next.js inlines into the "
    "client bundle.",
    [
        replace(
            "src/lib/supabase.ts",
            "process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,",
            "process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY!,",
        )
    ],
    [("AG-SECRET-001", "src/lib/supabase.ts#secret_env_public_prefix")],
)
data_case(
    "m56_anon_key_literal_in_client",
    "negative",
    "Hard-codes the anon (publishable) JWT in the client, which is public by design.",
    [
        replace(
            "src/lib/supabase.ts",
            "process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,",
            f"'{_fake_jwt('anon')}',",
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
        elif e[0] == "write_append":
            head_files[e[1]] = head_files[e[1]] + e[2]
        else:
            del head_files[e[1]]
    materialize(cdir / "base", base_files)
    materialize(cdir / "head", head_files)
    lines = [
        f"id: {c['id']}",
        f"kind: {c['kind']}",
        f"framework: {c['framework']}",
        f"description: {json.dumps(c['desc'])}",
        "expected:" + ("" if c["expected"] else " []"),
    ]
    for rule, key in c["expected"]:
        lines += [f"  - rule_id: {rule}", f'    key: "{key}"']
    (cdir / "case.yaml").write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    print("wrote", c["id"])
