from fastapi import APIRouter, Depends

from app.db import get_db
from app.deps import require_admin
from app.models import User

router = APIRouter()


@router.delete("/users/{user_id}")
def delete_user(user_id: int, admin: User = Depends(require_admin), db=Depends(get_db)):
    db.query(User).filter(User.id == user_id).delete()
    db.commit()
