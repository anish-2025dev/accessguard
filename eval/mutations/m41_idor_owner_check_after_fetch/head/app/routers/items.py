from fastapi import APIRouter, Depends, HTTPException

from app.db import get_db
from app.deps import get_current_user
from app.models import Item, User

router = APIRouter()


@router.get("/")
def list_items(db=Depends(get_db)):
    return db.query(Item).all()


@router.get("/{item_id}")
def read_item(item_id: int, user: User = Depends(get_current_user), db=Depends(get_db)):
    return db.query(Item).filter(Item.id == item_id, Item.owner_id == user.id).first()


@router.patch("/{item_id}")
def rename_item(
    item_id: int, title: str, user: User = Depends(get_current_user), db=Depends(get_db)
):
    item = db.query(Item).filter(Item.id == item_id).first()
    if item.owner_id != user.id:
        raise HTTPException(status_code=403)
    item.title = title
    db.commit()
