from fastapi import Depends, FastAPI

from app.deps import get_current_user

app = FastAPI(dependencies=[Depends(get_current_user)])


internal = FastAPI()


@internal.post("/reindex")
def reindex():
    return {"queued": True}


app.mount("/internal", internal)


@app.get("/reports")
def reports():
    return []
