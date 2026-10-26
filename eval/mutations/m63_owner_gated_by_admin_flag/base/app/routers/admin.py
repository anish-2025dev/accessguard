from fastapi import APIRouter, Depends

from app.deps import Account, check_admin

router = APIRouter()


@router.post("/settings", dependencies=[Depends(check_admin)])
def update_settings(body: dict) -> dict:
    return body


@router.delete("/cache", dependencies=[Depends(check_admin)])
def clear_cache(account: Account = Depends(check_admin)) -> dict:
    return {}
