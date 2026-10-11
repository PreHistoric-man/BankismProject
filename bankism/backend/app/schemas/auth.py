"""Authentication and principal schemas for Bankism Phase 2."""

from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field


class UserRole(str, Enum):
    """Fictional user roles in the Bankism prototype sandbox."""

    CUSTOMER = "CUSTOMER"
    APPROVER = "APPROVER"
    ADMIN = "ADMIN"


class AuthenticatedPrincipal(BaseModel):
    """Verified server-side principal context.

    Derived exclusively from verified authentication tokens/headers,
    never from untrusted client request bodies.
    """

    user_id: str = Field(..., description="Unique fictional user ID")
    username: str = Field(..., description="Fictional username (e.g. alice, bob, charlie)")
    role: UserRole = Field(default=UserRole.CUSTOMER, description="Role within the banking sandbox")
    session_id: str = Field(..., description="Active session tracking identifier")
    authorized_account_ids: List[str] = Field(
        default_factory=list,
        description="List of accounts this principal owns and is authorized to operate",
    )
    can_approve_transfers: bool = Field(
        default=False,
        description="Whether this principal holds authority to act as dual approver",
    )
