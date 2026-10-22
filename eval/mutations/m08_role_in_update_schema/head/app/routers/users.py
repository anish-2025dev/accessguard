from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.db import get_db
from app.deps import get_current_user
from app.models import User

router = APIRouter()


class UserUpdate(BaseModel):
    name: str | None = None
    role: str | None = None


@router.patch("/me")
def update_me(body: UserUpdate, user: User = Depends(get_current_user), db=Depends(get_db)):
    for key, value in body.model_dump(exclude_unset=True).items():
        setattr(user, key, value)
    db.commit()
    return user
