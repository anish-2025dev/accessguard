from http import HTTPStatus

from fastapi import Depends, Header, HTTPException

from app import settings


class Account:
    def __init__(self, id: str) -> None:
        self.id = id
        self.has_password = True


def check_account_exists(authorization: str = Header(...)) -> Account:
    if not authorization:
        raise HTTPException(status_code=401, detail="not authenticated")
    return Account(id=authorization.removeprefix("Bearer "))


def check_super_user(account: Account = Depends(check_account_exists)) -> Account:
    if account.id != settings.super_user:
        raise HTTPException(HTTPStatus.FORBIDDEN, "No super user privileges.")
    return account


def check_admin(account: Account = Depends(check_account_exists)) -> Account:
    if account.id != settings.super_user and account.id not in settings.admin_users:
        raise HTTPException(HTTPStatus.FORBIDDEN, "No admin privileges.")
    return account
