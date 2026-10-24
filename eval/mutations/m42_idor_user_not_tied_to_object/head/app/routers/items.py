from fastapi import APIRouter, Depends

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


@router.put("/{item_id}")
def update_item(item_id: int, title: str, user: User = Depends(get_current_user), db=Depends(get_db)):
    db.query(Item).filter(Item.id == item_id).update({"title": title})
    db.commit()
    return {"updated_by": user.id}
