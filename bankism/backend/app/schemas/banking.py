"""Simulated banking schemas for accounts, transactions, and Phase 2 transfer operations."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from ..authorization.tickets import AuthorizationTicket


class AccountType(str, Enum):
    """Fictional banking account types."""

    CHECKING = "CHECKING"
    SAVINGS = "SAVINGS"
    CREDIT = "CREDIT"
    MONEY_MARKET = "MONEY_MARKET"


class SimulatedAccount(BaseModel):
    """Simulated banking account object."""

    account_id: str
    user_id: str
    account_name: str
    account_type: AccountType
    balance: float
    currency: str = "USD"
    is_active: bool = True
    daily_transfer_limit: float = 15000.00


class SimulatedTransaction(BaseModel):
    """Simulated banking transaction record."""

    transaction_id: str
    source_account_id: str
    destination_account_id: str
    amount: float
    currency: str = "USD"
    memo: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    status: str = "COMPLETED"


class PrepareTransferRequest(BaseModel):
    """Request to prepare and authorize a simulated transfer."""

    source_account_id: str = Field(..., max_length=100, description="Source bank account")
    destination_account_id: str = Field(..., max_length=100, description="Destination account")
    amount: float = Field(..., gt=0.0, description="Transfer amount in dollars (e.g. 50.00)")
    currency: str = Field(default="USD", max_length=10, description="ISO currency code")
    memo: Optional[str] = Field(None, max_length=500, description="Optional payment reference")
    prompt: Optional[str] = Field(
        None,
        max_length=4000,
        description="Associated natural-language prompt to inspect with AI Security Firewall",
    )
    context: Optional[Dict[str, Any]] = Field(
        default_factory=dict,
        description="Optional behavioral context signals (e.g. simulated_hour_utc) for risk testing",
    )


class ConfirmTransferRequest(BaseModel):
    """Request to execute an authorized transfer using a signed ticket."""

    ticket: AuthorizationTicket = Field(..., description="Server-signed unforgeable authorization ticket")
    idempotency_key: Optional[str] = Field(
        None,
        max_length=120,
        description="Optional unique client idempotency key to prevent duplicates on retries",
    )


class DualApproveRequest(BaseModel):
    """Request by an authorized secondary approver to approve a high-risk transaction."""

    request_id: str = Field(..., max_length=100, description="Approval request identifier")


class AccountBalanceResponse(BaseModel):
    """Response containing authorized account balance."""

    account_id: str
    user_id: str
    account_name: str
    account_type: str
    balance_cents: int
    balance_dollars: float
    currency: str
    daily_limit_dollars: float
