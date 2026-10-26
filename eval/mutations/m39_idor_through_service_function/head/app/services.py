from app.models import Item


def archive(db, item_id):
    db.query(Item).filter(Item.id == item_id).update({"title": "archived"})
    db.commit()
