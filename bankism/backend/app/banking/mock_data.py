"""Simulated fictional accounts and mock data for security prototyping.

CRITICAL SECURITY NOTICE:
This module contains solely simulated, fictitious accounts for sandbox security evaluations.
No real financial institutions, ACH networks, or payment processors are integrated.
Transaction execution is strictly disabled in Phase 1.
"""

from typing import Dict, Optional
from ..schemas.banking import AccountType, SimulatedAccount

# Fictional test accounts
MOCK_ACCOUNTS: Dict[str, SimulatedAccount] = {
    "ACC-1001-CHK": SimulatedAccount(
        account_id="ACC-1001-CHK",
        user_id="USR-4401-ALICE",
        account_name="Everyday Checking",
        account_type=AccountType.CHECKING,
        balance=4820.50,
        currency="USD",
        daily_transfer_limit=5000.00,
    ),
    "ACC-2002-SAV": SimulatedAccount(
        account_id="ACC-2002-SAV",
        user_id="USR-4401-ALICE",
        account_name="High-Yield Savings",
        account_type=AccountType.SAVINGS,
        balance=32500.00,
        currency="USD",
        daily_transfer_limit=25000.00,
    ),
    "ACC-3003-BUS": SimulatedAccount(
        account_id="ACC-3003-BUS",
        user_id="USR-8899-BOB",
        account_name="Commercial Operating",
        account_type=AccountType.CHECKING,
        balance=145000.00,
        currency="USD",
        daily_transfer_limit=50000.00,
    ),
}


def get_account_by_id(account_id: str) -> Optional[SimulatedAccount]:
    """Retrieve simulated account by identifier if exists."""
    return MOCK_ACCOUNTS.get(account_id)
