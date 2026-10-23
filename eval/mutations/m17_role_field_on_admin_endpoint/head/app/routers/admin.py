from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.db import get_db
from app.deps import require_admin
from app.models import User

router = APIRouter()


class AdminUserUpdate(BaseModel):
    role: str | None = None


@router.patch("/users/{user_id}")
def admin_update(user_id: int, body: AdminUserUpdate, admin: User = Depends(require_admin), db=Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    for key, value in body.model_dump(exclude_unset=True).items():
        setattr(user, key, value)
    db.commit()


@router.delete("/users/{user_id}")
def delete_user(user_id: int, admin: User = Depends(require_admin), db=Depends(get_db)):
    db.query(User).filter(User.id == user_id).delete()
    db.commit()
