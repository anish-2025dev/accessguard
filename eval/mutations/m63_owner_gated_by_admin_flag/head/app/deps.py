from http import HTTPStatus

from fastapi import Depends, Header, HTTPException

from app import settings


class Account:
    def __init__(self, id: str) -> None:
        self.id = id


class Document:
    def __init__(self, id: str, owner_id: str) -> None:
        self.id = id
        self.owner_id = owner_id


def load_document(doc_id: str) -> Document:
    return Document(id=doc_id, owner_id="someone")


def check_account_exists(authorization: str = Header(...)) -> Account:
    if not authorization:
        raise HTTPException(status_code=401, detail="not authenticated")
    return Account(id=authorization.removeprefix("Bearer "))


def check_admin(account: Account = Depends(check_account_exists)) -> Account:
    if account.id != settings.super_user:
        raise HTTPException(HTTPStatus.FORBIDDEN, "No admin privileges.")
    return account


def check_owner_or_admin(doc_id: str, account: Account = Depends(check_account_exists)) -> Account:
    doc = load_document(doc_id)
    # Per-object ownership, merely gated by a global flag: NOT a privilege/role check.
    if settings.admin_mode and account.id != doc.owner_id:
        raise HTTPException(HTTPStatus.FORBIDDEN, "Not your document.")
    return account
