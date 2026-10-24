from fastapi import APIRouter, Depends

from app.db import get_db
from app.deps import require_admin
from app.models import User

router = APIRouter()


def promote(user_id: int, db=Depends(get_db)):
    db.query(User).filter(User.id == user_id).update({"role": "admin"})


router.add_api_route("/users/{user_id}/promote", promote, methods=["POST"])


@router.delete("/users/{user_id}")
def delete_user(user_id: int, admin: User = Depends(require_admin), db=Depends(get_db)):
    db.query(User).filter(User.id == user_id).delete()
    db.commit()
