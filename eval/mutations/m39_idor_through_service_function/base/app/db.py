from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

SessionLocal = sessionmaker(bind=create_engine("sqlite://"))


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
