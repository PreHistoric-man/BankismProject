"""
Simulated Principal Resolution and Ownership Authorization Module
"""
from typing import Dict, List, Optional
from fastapi import Request, HTTPException, status
from pydantic import BaseModel
from ..schemas.common import UserRole


class Principal(BaseModel):
    user_id: str
    username: str
    role: UserRole
    authorized_accounts: List[str]


# Fictional Directory of Demo Principals
DEMO_DIRECTORY: Dict[str, Principal] = {
    "alice": Principal(
        user_id="USR-4401-ALICE",
        username="alice",
        role=UserRole.CUSTOMER,
        authorized_accounts=["ACC-1001-CHK", "ACC-2002-SAV"],
    ),
    "bob": Principal(
        user_id="USR-8899-BOB",
        username="bob",
        role=UserRole.CUSTOMER,
        authorized_accounts=["ACC-3003-BUS"],
    ),
    "charlie": Principal(
        user_id="USR-9900-CHARLIE",
        username="charlie",
        role=UserRole.APPROVER,
        authorized_accounts=[],  # Risk Officer does not hold customer accounts
    ),
    "dave": Principal(
        user_id="USR-1100-DAVE",
        username="dave",
        role=UserRole.CUSTOMER,
        authorized_accounts=["ACC-4004-CHK"],
    ),
}


def resolve_authenticated_principal(request: Request) -> Principal:
    """
    Derives identity exclusively from trusted server-side request context.
    Client-supplied user_id or roles in request payloads are strictly ignored.
    """
    user_header = request.headers.get("X-Bankism-Mock-User")
    if not user_header:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            user_header = auth_header[7:].strip()

    if not user_header or user_header.strip() == "":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="AUTHENTICATION_REQUIRED: 'X-Bankism-Mock-User' header or Bearer token missing."
        )

    clean_user = user_header.strip().lower()
    principal = DEMO_DIRECTORY.get(clean_user)
    if not principal:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"INVALID_PRINCIPAL: Principal '{clean_user}' not recognized in fictional demo directory."
        )

    return principal


def verify_account_ownership(principal: Principal, account_id: str) -> None:
    """
    Ensures caller owns the designated account. Cross-account access fails closed (403 Forbidden).
    """
    if account_id not in principal.authorized_accounts:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"ACCOUNT_ACCESS_DENIED: Principal '{principal.username}' does not own '{account_id}'."
        )
