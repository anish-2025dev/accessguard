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
