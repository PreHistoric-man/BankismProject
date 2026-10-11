"""Simulated banking schemas for accounts and transactions."""

from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field


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
    status: str = "PENDING_PHASE1_GUARD"
