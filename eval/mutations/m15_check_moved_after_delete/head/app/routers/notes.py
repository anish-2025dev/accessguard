from fastapi import APIRouter, Depends, HTTPException

from app.db import get_db
from app.deps import get_current_user
from app.models import Item, User

router = APIRouter()


@router.delete("/{item_id}")
def delete_note(item_id: int, user: User = Depends(get_current_user), db=Depends(get_db)):
    item = db.query(Item).filter(Item.id == item_id).first()
    db.query(Item).filter(Item.id == item_id).delete()
    db.commit()
    if item.owner_id != user.id:
        raise HTTPException(status_code=403, detail="not yours")
