from fastapi import APIRouter

from app.routers import admin_users

router = APIRouter()
router.include_router(admin_users.router)
