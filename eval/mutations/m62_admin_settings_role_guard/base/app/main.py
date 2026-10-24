from fastapi import FastAPI

from app.routers import admin

app = FastAPI(title="Example")
app.include_router(admin.router, prefix="/admin/api/v1")
