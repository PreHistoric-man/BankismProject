"""Ledger domain models and minor-unit currency arithmetic utilities."""

from datetime import datetime, timezone
from decimal import Decimal, ROUND_HALF_UP
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field


class TransactionStatus(str, Enum):
    """Simulated transaction status in the SQLite ledger."""

    PENDING = "PENDING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    REVERTED = "REVERTED"


SUPPORTED_CURRENCIES = {"USD"}


def dollars_to_cents(amount: float | str | int | Decimal) -> int:
    """Convert standard monetary dollars to integer minor units (cents) safely.

    Uses Python Decimal to prevent binary floating-point representation inaccuracies.
    """
    if isinstance(amount, (float, int)):
        dec = Decimal(str(amount))
    elif isinstance(amount, str):
        dec = Decimal(amount)
    else:
        dec = amount

    # Round half up to 2 decimal places and convert to integer cents
    cents = int((dec * Decimal(100)).quantize(Decimal("1"), rounding=ROUND_HALF_UP))
    if cents < 0:
        raise ValueError("Monetary amount cannot be negative")
    return cents


def cents_to_dollars(cents: int) -> float:
    """Convert integer minor units (cents) to standard float dollars for display."""
    if not isinstance(cents, int):
        raise TypeError("Cents must be an integer minor unit")
    dec = Decimal(cents) / Decimal(100)
    return float(dec)


class AccountRecord(BaseModel):
    """Account database representation."""

    account_id: str
    user_id: str
    account_name: str
    account_type: str
    balance_cents: int
    currency: str = "USD"
    daily_limit_cents: int
    is_active: bool = True

    @property
    def balance_dollars(self) -> float:
        return cents_to_dollars(self.balance_cents)

    @property
    def daily_limit_dollars(self) -> float:
        return cents_to_dollars(self.daily_limit_cents)


class TransactionRecord(BaseModel):
    """Completed simulated transaction record."""

    transaction_id: str
    idempotency_key: str
    source_account_id: str
    destination_account_id: str
    amount_cents: int
    currency: str = "USD"
    memo: Optional[str] = None
    status: TransactionStatus = TransactionStatus.COMPLETED
    created_at: str

    @property
    def amount_dollars(self) -> float:
        return cents_to_dollars(self.amount_cents)
