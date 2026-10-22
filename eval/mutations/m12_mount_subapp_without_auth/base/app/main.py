from fastapi import Depends, FastAPI

from app.deps import get_current_user

app = FastAPI(dependencies=[Depends(get_current_user)])


@app.get("/reports")
def reports():
    return []
