from fastapi import APIRouter

router = APIRouter()


@router.get("/health")
def health():
    return {"ok": True}


@router.get("/status")
def status():
    return {"version": "1"}
