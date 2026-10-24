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


@router.post("/broadcast")
def broadcast(user=Depends(get_current_user)):
    return {}
