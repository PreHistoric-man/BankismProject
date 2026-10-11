"""Trusted Identity and Account Authorization module for Bankism Phase 2.

CRITICAL ARCHITECTURAL BOUNDARY:
This module provides a strictly server-side verified principal context for local
development and research prototyping. Client-provided user_id or account_id in
request payloads are NEVER accepted as proof of identity.

All account queries and transactions derive authorization exclusively from
the verified AuthenticatedPrincipal returned by this module.
"""

from typing import Dict, Optional
from fastapi import Header, HTTPException, status
from ..schemas.auth import AuthenticatedPrincipal, UserRole

# Fictional users registry for local prototype sandbox
# In production, this would be backed by OAuth2/OIDC/mTLS.
FICTIONAL_USERS: Dict[str, Dict] = {
    "alice": {
        "user_id": "USR-4401-ALICE",
        "username": "alice",
        "role": UserRole.CUSTOMER,
        "authorized_account_ids": ["ACC-1001-CHK", "ACC-2002-SAV"],
        "can_approve_transfers": False,
        "token": "mock-token-alice-secret-key-1001",
    },
    "bob": {
        "user_id": "USR-8899-BOB",
        "username": "bob",
        "role": UserRole.CUSTOMER,
        "authorized_account_ids": ["ACC-3003-BUS"],
        "can_approve_transfers": False,
        "token": "mock-token-bob-secret-key-8899",
    },
    "charlie": {
        "user_id": "USR-9900-CHARLIE",
        "username": "charlie",
        "role": UserRole.APPROVER,
        "authorized_account_ids": [],
        "can_approve_transfers": True,
        "token": "mock-token-charlie-risk-officer-9900",
    },
    "dave": {
        "user_id": "USR-1100-DAVE",
        "username": "dave",
        "role": UserRole.CUSTOMER,
        "authorized_account_ids": ["ACC-4004-CHK"],
        "can_approve_transfers": False,
        "token": "mock-token-dave-secret-key-1100",
    },
}

# Token lookup mapping
TOKEN_TO_USER: Dict[str, str] = {
    u_data["token"]: username for username, u_data in FICTIONAL_USERS.items()
}


def get_authenticated_principal(
    x_bankism_mock_user: Optional[str] = Header(None, alias="X-Bankism-Mock-User"),
    authorization: Optional[str] = Header(None, alias="Authorization"),
) -> AuthenticatedPrincipal:
    """Derive authenticated principal from verified server-side identity context.

    Accepts either:
    1. Header: X-Bankism-Mock-User: <username> (e.g. alice, bob, charlie)
    2. Header: Authorization: Bearer <mock-token-...>

    FAILS CLOSED (HTTP 401) if neither is provided or if identity is unknown.
    """
    matched_user_key: Optional[str] = None

    # 1. If Authorization header is provided, strictly validate it (fail closed on invalid token)
    if authorization:
        if not authorization.lower().startswith("bearer "):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={
                    "error": "INVALID_AUTH_SCHEME",
                    "message": "Unsupported authorization scheme. Use 'Bearer <token>'.",
                },
                headers={"WWW-Authenticate": "Bearer"},
            )
        token = authorization[7:].strip()
        matched_user_key = TOKEN_TO_USER.get(token)
        if not matched_user_key:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={
                    "error": "INVALID_BEARER_TOKEN",
                    "message": "Provided Bearer token is invalid, unrecognized, or expired.",
                },
                headers={"WWW-Authenticate": "Bearer"},
            )

        # If X-Bankism-Mock-User is ALSO provided alongside Bearer token, they MUST match
        if x_bankism_mock_user:
            user_clean = x_bankism_mock_user.strip().lower()
            if user_clean != matched_user_key:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail={
                        "error": "CONFLICTING_IDENTITY_CLAIMS",
                        "message": (
                            f"Conflicting identity headers: Bearer token is for '{matched_user_key}', "
                            f"but X-Bankism-Mock-User claims '{user_clean}'."
                        ),
                    },
                    headers={"WWW-Authenticate": "Bearer"},
                )

    # 2. If no Authorization header, validate X-Bankism-Mock-User header
    elif x_bankism_mock_user:
        user_clean = x_bankism_mock_user.strip().lower()
        if user_clean in FICTIONAL_USERS:
            matched_user_key = user_clean

    if not matched_user_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": "AUTHENTICATION_REQUIRED",
                "message": (
                    "Missing or invalid authentication context. For local prototype development, "
                    "provide 'X-Bankism-Mock-User: alice' or 'Authorization: Bearer mock-token-alice-secret-key-1001'."
                ),
            },
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_info = FICTIONAL_USERS[matched_user_key]
    return AuthenticatedPrincipal(
        user_id=user_info["user_id"],
        username=user_info["username"],
        role=user_info["role"],
        session_id=f"sess-{matched_user_key}-local-verified",
        authorized_account_ids=user_info["authorized_account_ids"],
        can_approve_transfers=user_info["can_approve_transfers"],
    )


def authorize_account_ownership(principal: AuthenticatedPrincipal, account_id: str) -> None:
    """Enforce strict account access boundary.

    Validates that the source account belongs to the authenticated principal.
    FAILS CLOSED (HTTP 403 Forbidden) if the principal does not own the account.
    """
    if account_id not in principal.authorized_account_ids:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "ACCOUNT_ACCESS_DENIED",
                "message": (
                    f"Principal '{principal.username}' ({principal.user_id}) does not own "
                    f"or hold authorization for account '{account_id}'."
                ),
                "account_id": account_id,
            },
        )


def authorize_dual_approver(principal: AuthenticatedPrincipal, initiator_user_id: str) -> None:
    """Enforce dual approval authorization constraints.

    1. Approver must hold APPROVER role (can_approve_transfers == True).
    2. Approver must be distinct from the initiating principal.
    """
    if not principal.can_approve_transfers:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "INSUFFICIENT_APPROVAL_PERMISSIONS",
                "message": f"Principal '{principal.username}' does not hold dual-approver role permissions.",
            },
        )

    if principal.user_id == initiator_user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "SELF_APPROVAL_PROHIBITED",
                "message": "Initiating principal cannot approve their own high-risk transaction.",
                "initiator_user_id": initiator_user_id,
            },
        )
