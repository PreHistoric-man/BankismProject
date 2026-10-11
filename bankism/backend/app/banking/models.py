"""
Ledger and Banking Domain Data Models
"""
from typing import Optional
from pydantic import BaseModel, Field


class Account(BaseModel):
    account_id: str
    name: str
    owner_user_id: str
    balance_cents: int
    daily_limit_cents: int
    created_at_utc: str

    @property
    def balance_dollars(self) -> float:
        return self.balance_cents / 100.0

    @property
    def daily_limit_dollars(self) -> float:
        return self.daily_limit_cents / 100.0


class SimulatedTransaction(BaseModel):
    tx_id: str
    user_id: str
    source_account_id: str
    destination_account_id: str
    amount_cents: int
    currency: str = "USD"
    memo: Optional[str] = None
    status: str
    created_at_utc: str
    audit_event_hash: Optional[str] = None

    @property
    def amount_dollars(self) -> float:
        return self.amount_cents / 100.0


def dollars_to_cents(dollars: float) -> int:
    """
    Converts floating dollar amount to exact integer minor units (cents).
    Prevents floating-point arithmetic drift.
    """
    return int(round(dollars * 100))
