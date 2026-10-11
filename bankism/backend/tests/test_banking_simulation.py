"""Tests for simulated banking mock data and guardrails."""

import sys
from pathlib import Path

backend_dir = Path(__file__).resolve().parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from app.banking.mock_data import MOCK_ACCOUNTS, get_account_by_id
from app.banking.models import AccountType


def test_mock_accounts_loaded():
    assert "ACC-1001-CHK" in MOCK_ACCOUNTS
    account = get_account_by_id("ACC-1001-CHK")
    assert account is not None
    assert account.account_type == AccountType.CHECKING
    assert account.balance > 0
    assert account.daily_transfer_limit > 0


def test_nonexistent_account_returns_none():
    assert get_account_by_id("ACC-NONEXISTENT") is None
