"""
Banking Ledger Read Operations Module
"""
import sqlite3
from typing import List, Optional
from fastapi import HTTPException, status
from .database import get_db_connection
from .models import Account, SimulatedTransaction


def get_user_accounts(conn: sqlite3.Connection, user_id: str) -> List[Account]:
    """
    Returns accounts owned by the authenticated user.
    """
    cur = conn.execute(
        "SELECT account_id, name, owner_user_id, balance_cents, daily_limit_cents, created_at_utc FROM accounts WHERE owner_user_id = ? ORDER BY account_id;",
        (user_id,)
    )
    return [Account(**dict(row)) for row in cur.fetchall()]


def get_account_by_id(conn: sqlite3.Connection, account_id: str) -> Optional[Account]:
    """
    Retrieves an account by its unique identifier.
    """
    cur = conn.execute(
        "SELECT account_id, name, owner_user_id, balance_cents, daily_limit_cents, created_at_utc FROM accounts WHERE account_id = ?;",
        (account_id,)
    )
    row = cur.fetchone()
    if not row:
        return None
    return Account(**dict(row))


def record_transfer_attempt(
    conn: sqlite3.Connection,
    attempt_id: str,
    user_id: str,
    src: str,
    dst: str,
    amount_cents: int,
    status_code: str,
    reason: str,
    created_at_utc: str
) -> None:
    """
    Records an outgoing transfer attempt (validation rejected, firewall blocked, or prepared).
    """
    conn.execute(
        "INSERT INTO transfer_attempts (attempt_id, user_id, source_account_id, destination_account_id, amount_cents, status, reason, created_at_utc) VALUES (?, ?, ?, ?, ?, ?, ?, ?);",
        (attempt_id, user_id, src, dst, amount_cents, status_code, reason, created_at_utc)
    )
