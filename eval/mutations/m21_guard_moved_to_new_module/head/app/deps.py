from fastapi import Depends, HTTPException

from app.models import User
from app.security import get_current_user


def require_admin(user: User = Depends(get_current_user)) -> User:
    if user.role != "admin" or not user.is_active:
        raise HTTPException(status_code=403, detail="admin only")
    return user
