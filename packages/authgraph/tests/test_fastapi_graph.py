from pathlib import Path

from authgraph.facts.models import GuardKind, Verdict

from .helpers import DEPS, endpoints


def test_prefixes_include_deps_and_double_include(tmp_path: Path) -> None:
    eps = endpoints(
        tmp_path,
        {
            "app/__init__.py": "",
            "app/deps.py": DEPS,
            "app/items.py": """
                from fastapi import APIRouter
                router = APIRouter(prefix="/items")
                @router.get("/{item_id}")
                def read(item_id: int): ...
            """,
            "app/main.py": """
                from fastapi import FastAPI, Depends
                from app import items
                from app.deps import get_current_user
                app = FastAPI()
                app.include_router(items.router, prefix="/v1",
                                   dependencies=[Depends(get_current_user)])
                app.include_router(items.router, prefix="/public")
            """,
        },
    )
    assert eps["GET /v1/items/{item_id}"].authn == Verdict.AUTH
    g = eps["GET /v1/items/{item_id}"].guards[0]
    assert g.symbol == "app.deps.get_current_user" and g.inherited_from is not None
    # Every include path is its own endpoint (PLAN.md §6.4).
    assert eps["GET /public/items/{item_id}"].authn == Verdict.NO_AUTH


def test_mounted_subapp_does_not_inherit_app_dependencies(tmp_path: Path) -> None:
    eps = endpoints(
        tmp_path,
        {
            "deps.py": DEPS,
            "main.py": """
                from fastapi import FastAPI, Depends
                from deps import get_current_user
                app = FastAPI(dependencies=[Depends(get_current_user)])
                sub = FastAPI()
                @sub.post("/x")
                def x(): ...
                @app.get("/y")
                def y(): ...
                app.mount("/sub", sub)
            """,
        },
    )
    assert eps["GET /y"].authn == Verdict.AUTH
    assert eps["POST /sub/x"].authn == Verdict.NO_AUTH
    assert eps["POST /sub/x"].mounted_under_auth


def test_annotated_alias_security_and_role_guard(tmp_path: Path) -> None:
    eps = endpoints(
        tmp_path,
        {
            "deps.py": DEPS
            + """
from typing import Annotated
CurrentUser = Annotated[dict, Depends(get_current_user)]
""",
            "main.py": """
                from fastapi import FastAPI, Security
                from deps import CurrentUser, require_admin
                app = FastAPI()
                @app.get("/me")
                def me(user: CurrentUser): ...
                @app.delete("/admin/{id}")
                def delete(id: int, admin=Security(require_admin, scopes=["admin"])): ...
            """,
        },
    )
    assert eps["GET /me"].authn == Verdict.AUTH
    kinds = {g.kind for g in eps["DELETE /admin/{id}"].guards}
    assert {GuardKind.AUTHZ_ROLE, GuardKind.AUTHN} <= kinds


def test_constant_folded_prefix_and_factory_app(tmp_path: Path) -> None:
    eps = endpoints(
        tmp_path,
        {
            "core/__init__.py": "",
            "core/config.py": """
                class Settings:
                    API_V1_STR: str = "/api/v1"
                settings = Settings()
            """,
            "main.py": """
                from fastapi import FastAPI, APIRouter
                from core.config import settings
                router = APIRouter()
                @router.api_route("/ping", methods=["GET", "POST"])
                def ping(): ...
                def get_application() -> FastAPI:
                    application = FastAPI()
                    application.include_router(router, prefix=settings.API_V1_STR)
                    return application
                app = get_application()
            """,
        },
    )
    assert {"GET /api/v1/ping", "POST /api/v1/ping"} <= set(eps)


def test_dynamic_prefix_is_unknown_not_no_auth(tmp_path: Path) -> None:
    eps = endpoints(
        tmp_path,
        {
            "main.py": """
                import os
                from fastapi import FastAPI, APIRouter
                router = APIRouter()
                @router.post("/x")
                def x(): ...
                app = FastAPI()
                app.include_router(router, prefix=os.environ["PREFIX"])
            """,
        },
    )
    (ep,) = eps.values()
    assert ep.path == "/<dynamic>/x" and ep.authn == Verdict.UNKNOWN


def test_unresolved_auth_dependency_is_unknown(tmp_path: Path) -> None:
    eps = endpoints(
        tmp_path,
        {
            "main.py": """
                from fastapi import FastAPI, Depends
                from somelib.auth import get_current_principal
                app = FastAPI()
                @app.post("/x")
                def x(p=Depends(get_current_principal)): ...
                @app.post("/y")
                def y(db=Depends(get_session)): ...
            """,
        },
    )
    assert eps["POST /x"].authn == Verdict.UNKNOWN
    assert eps["POST /y"].authn == Verdict.NO_AUTH


def test_security_schemes_optional_and_fastapi_users(tmp_path: Path) -> None:
    eps = endpoints(
        tmp_path,
        {
            "main.py": """
                from fastapi import FastAPI, Depends
                from fastapi.security import OAuth2PasswordBearer
                from fastapi_users import FastAPIUsers
                required = OAuth2PasswordBearer(tokenUrl="t")
                optional = OAuth2PasswordBearer(tokenUrl="t", auto_error=False)
                fastapi_users = FastAPIUsers(get_user_manager, [backend])
                current_superuser = fastapi_users.current_user(active=True, superuser=True)
                app = FastAPI()
                @app.get("/a")
                def a(t=Depends(required)): ...
                @app.get("/b")
                def b(t=Depends(optional)): ...
                @app.get("/c")
                def c(u=Depends(current_superuser)): ...
                @app.get("/d")
                def d(u=Depends(fastapi_users.current_user(optional=True))): ...
            """,
        },
    )
    assert eps["GET /a"].authn == Verdict.AUTH
    assert eps["GET /b"].authn == Verdict.NO_AUTH
    assert eps["GET /c"].guards[0].kind == GuardKind.AUTHZ_ROLE
    assert eps["GET /d"].authn == Verdict.NO_AUTH


def test_class_dependency_and_dependency_factory(tmp_path: Path) -> None:
    eps = endpoints(
        tmp_path,
        {
            "deps.py": DEPS,
            "main.py": """
                from fastapi import FastAPI, Depends, HTTPException
                from deps import get_current_user
                class RoleChecker:
                    def __init__(self, roles): self.roles = roles
                    def __call__(self, user=Depends(get_current_user)):
                        if user["role"] not in self.roles:
                            raise HTTPException(status_code=403)
                def require_role(role):
                    def checker(user=Depends(get_current_user)):
                        if user["role"] != role:
                            raise HTTPException(403)
                    return checker
                app = FastAPI()
                @app.delete("/a")
                def a(_=Depends(RoleChecker(["admin"]))): ...
                @app.delete("/b", dependencies=[Depends(require_role("admin"))])
                def b(): ...
            """,
        },
    )
    for ep in ("DELETE /a", "DELETE /b"):
        assert GuardKind.AUTHZ_ROLE in {g.kind for g in eps[ep].guards}, ep


def test_add_api_route_and_inline_owner_check(tmp_path: Path) -> None:
    eps = endpoints(
        tmp_path,
        {
            "main.py": """
                from fastapi import FastAPI, HTTPException
                app = FastAPI()
                def handler(item_id: int, user=None):
                    item = load(item_id)
                    if item.owner_id != user.id:
                        raise HTTPException(status_code=404)
                    return item
                app.add_api_route("/items/{item_id}", handler, methods=["GET"])
            """,
        },
    )
    assert eps["GET /items/{item_id}"].guards[0].kind == GuardKind.AUTHZ_OWNER


def test_routes_on_routers_never_included_without_app_are_roots(tmp_path: Path) -> None:
    eps = endpoints(
        tmp_path,
        {
            "r.py": """
                from fastapi import APIRouter
                router = APIRouter(prefix="/lib")
                @router.get("/x")
                def x(): ...
            """,
        },
    )
    assert set(eps) == {"GET /lib/x"}


def test_cross_module_factory_binds_router_parameter(tmp_path: Path) -> None:
    eps = endpoints(
        tmp_path,
        {
            "src/__init__.py": "",
            "src/factory.py": """
                from fastapi import FastAPI, APIRouter
                def create_application(router: APIRouter, **kw) -> FastAPI:
                    application = FastAPI()
                    application.include_router(router, prefix="/api")
                    return application
            """,
            "src/api.py": """
                from fastapi import APIRouter
                router = APIRouter()
                @router.delete("/x")
                def x(): ...
            """,
            "src/main.py": """
                from .factory import create_application
                from .api import router
                app = create_application(router=router, title="t")
            """,
        },
    )
    assert set(eps) == {"DELETE /api/x"}


def test_flag_selected_dependency_factory(tmp_path: Path) -> None:
    eps = endpoints(
        tmp_path,
        {
            "jwt.py": """
                from fastapi import Header, HTTPException
                def _get_user(authorization: str = Header(...)):
                    if not authorization:
                        raise HTTPException(status_code=401)
                def _get_user_optional(authorization: str = Header(None)):
                    return None
                def get_authorizer(*, required: bool = True):
                    if required:
                        return _get_user
                    else:
                        return _get_user_optional
            """,
            "main.py": """
                from fastapi import FastAPI, Depends
                from jwt import get_authorizer
                app = FastAPI()
                @app.put("/user")
                def put(u=Depends(get_authorizer())): ...
                @app.get("/profile")
                def get(u=Depends(get_authorizer(required=False))): ...
                @app.get("/dyn")
                def dyn(u=Depends(get_authorizer(required=FLAG))): ...
            """,
        },
    )
    assert eps["PUT /user"].authn == Verdict.AUTH
    assert eps["GET /profile"].authn == Verdict.NO_AUTH
    assert eps["GET /dyn"].authn == Verdict.UNKNOWN


def test_exception_defined_in_another_module(tmp_path: Path) -> None:
    eps = endpoints(
        tmp_path,
        {
            "exc.py": "from fastapi import HTTPException, status\n"
            "privileges_exception = HTTPException(status_code=status.HTTP_403_FORBIDDEN)\n",
            "main.py": """
                from fastapi import FastAPI, Depends
                from exc import privileges_exception
                def get_current_superuser(user=None):
                    if not user.is_superuser:
                        raise privileges_exception
                app = FastAPI()
                @app.delete("/x")
                def x(u=Depends(get_current_superuser)): ...
            """,
        },
    )
    assert eps["DELETE /x"].guards[0].kind == GuardKind.AUTHZ_ROLE


def test_redefined_handler_names_keep_both_routes(tmp_path: Path) -> None:
    eps = endpoints(
        tmp_path,
        {
            "main.py": """
                from fastapi import FastAPI
                app = FastAPI()
                @app.get("/a")
                def view(): ...
                @app.get("/b")
                def view(): ...
            """,
        },
    )
    assert set(eps) == {"GET /a", "GET /b"}


def test_router_subclass_and_class_based_view(tmp_path: Path) -> None:
    eps = endpoints(
        tmp_path,
        {
            "deps.py": DEPS,
            "routers.py": """
                from fastapi import APIRouter, Depends
                from deps import get_current_user
                class UserAPIRouter(APIRouter):
                    def __init__(self, prefix: str = "", **kwargs):
                        super().__init__(prefix=prefix, dependencies=[Depends(get_current_user)], **kwargs)
            """,
            "base.py": """
                from fastapi import Depends
                from deps import get_current_user
                class BaseUserController:
                    user: dict = Depends(get_current_user)
            """,
            "main.py": """
                from fastapi import FastAPI, APIRouter
                from routers import UserAPIRouter
                from base import BaseUserController
                users = UserAPIRouter(prefix="/u")
                plain = APIRouter(prefix="/c")
                @users.post("/a")
                def a(): ...
                class RecipeController(BaseUserController):
                    @plain.post("/b")
                    def b(self): ...
                app = FastAPI()
                app.include_router(users)
                app.include_router(plain)
            """,
        },
    )
    assert eps["POST /u/a"].authn == Verdict.AUTH
    assert eps["POST /c/b"].authn == Verdict.AUTH


def test_factory_returning_depends_of_class_instance(tmp_path: Path) -> None:
    eps = endpoints(
        tmp_path,
        {
            "perm.py": """
                from fastapi import Depends, HTTPException
                class RequirePermission:
                    def __init__(self, perm): self.perm = perm
                    def __call__(self, user=None):
                        if self.perm not in user.permissions:
                            raise HTTPException(status_code=403)
                def require(perm):
                    return Depends(RequirePermission(perm))
            """,
            "main.py": """
                from fastapi import FastAPI
                from perm import require
                app = FastAPI()
                @app.post("/invite", dependencies=[require("invite")])
                def invite(): ...
            """,
        },
    )
    assert eps["POST /invite"].authn == Verdict.AUTH


def test_403_after_scheme_is_authn_but_after_user_is_authz(tmp_path: Path) -> None:
    eps = endpoints(
        tmp_path,
        {
            "main.py": """
                from fastapi import FastAPI, Depends, HTTPException
                from fastapi.security import OAuth2PasswordBearer
                scheme = OAuth2PasswordBearer(tokenUrl="t")
                def get_current_user(token: str = Depends(scheme)):
                    if not valid(token):
                        raise HTTPException(status_code=403)
                def can_invite(user=Depends(get_current_user)):
                    if not check(user):
                        raise HTTPException(status_code=403)
                app = FastAPI()
                @app.post("/x")
                def x(u=Depends(can_invite)): ...
            """,
        },
    )
    kinds = {g.symbol.split(".")[-1]: g.kind for g in eps["POST /x"].guards}
    assert kinds["get_current_user"] == GuardKind.AUTHN
    assert kinds["can_invite"] == GuardKind.AUTHZ_ROLE


def test_decorator_applied_by_hand(tmp_path: Path) -> None:
    eps = endpoints(
        tmp_path,
        {
            "main.py": """
                from fastapi import FastAPI, APIRouter
                router = APIRouter()
                def register_user(): ...
                if True:
                    register_user = router.post("/register")(register_user)
                app = FastAPI()
                app.include_router(router, prefix="/auth")
            """,
        },
    )
    assert set(eps) == {"POST /auth/register"}


def test_routers_included_from_lifespan_through_helpers(tmp_path: Path) -> None:
    eps = endpoints(
        tmp_path,
        {
            "core.py": """
                from fastapi import APIRouter, FastAPI
                router = APIRouter(prefix="/api")
                @router.get("/wallet")
                def wallet(): ...
                def init_core_routers(app: FastAPI):
                    app.include_router(router)
            """,
            "main.py": """
                from contextlib import asynccontextmanager
                from fastapi import FastAPI
                from core import init_core_routers
                async def startup(app: FastAPI):
                    init_core_routers(app)
                @asynccontextmanager
                async def lifespan(app: FastAPI):
                    await startup(app)
                    yield
                def create_app() -> FastAPI:
                    app = FastAPI(lifespan=lifespan)
                    return app
                app = create_app()
            """,
        },
    )
    assert set(eps) == {"GET /api/wallet"}


def test_guard_delegating_to_checker_class(tmp_path: Path) -> None:
    eps = endpoints(
        tmp_path,
        {
            "main.py": """
                from fastapi import FastAPI, Depends, HTTPException, Request
                class BaseKeyChecker:
                    def _extract(self, request):
                        if "X-Api-Key" not in request.headers:
                            raise HTTPException(status_code=401)
                class KeyChecker(BaseKeyChecker):
                    async def __call__(self, request):
                        return self._extract(request)
                async def require_admin_key(request: Request):
                    check = KeyChecker()
                    return await check(request)
                app = FastAPI()
                @app.delete("/wallet")
                def delete_wallet(k=Depends(require_admin_key)): ...
            """,
        },
    )
    assert eps["DELETE /wallet"].authn == Verdict.AUTH


def test_param_default_named_like_the_param_resolves_outside(tmp_path: Path) -> None:
    eps = endpoints(
        tmp_path,
        {
            "main.py": """
                from fastapi import FastAPI, Security
                from fastapi.security import APIKeyHeader
                api_key_header = APIKeyHeader(name="X-Api-Key")
                app = FastAPI()
                @app.get("/w")
                def w(api_key_header: str = Security(api_key_header)): ...
            """,
        },
    )
    assert eps["GET /w"].authn == Verdict.AUTH
