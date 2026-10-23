from fastapi import Depends, FastAPI

from app.deps import get_current_user
from app.routers import admin, items, public, users

app = FastAPI(title="Example")
app.include_router(public.router)
app.include_router(items.router, prefix="/items")
app.include_router(users.router, prefix="/users", dependencies=[Depends(get_current_user)])
app.include_router(admin.router, prefix="/admin")
