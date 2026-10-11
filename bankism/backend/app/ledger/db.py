"""SQLite database initialization, migration, and connection management for Bankism."""

import os
import sqlite3
from contextlib import contextmanager
from typing import Generator, Optional
from ..config import get_settings


def get_default_db_path() -> str:
    """Return configured SQLite database path."""
    return get_settings().database_path


@contextmanager
def get_db_connection(db_path: Optional[str] = None) -> Generator[sqlite3.Connection, None, None]:
    """Provide a managed SQLite database connection with row factory and foreign keys."""
    path = db_path or get_default_db_path()
    conn = sqlite3.connect(path, timeout=10.0, isolation_level=None)  # autocommit mode; transactions managed explicitly
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA busy_timeout = 5000;")
        yield conn
    finally:
        conn.close()


def init_ledger_database(db_path: Optional[str] = None) -> None:
    """Initialize schema tables and fictional sandbox seed data idempotently.

    Will NOT destroy existing data on application restart.
    """
    path = db_path or get_default_db_path()

    with get_db_connection(path) as conn:
        conn.execute("BEGIN IMMEDIATE;")
        try:
            # 1. Schema migrations tracker
            conn.execute("""
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    version INTEGER PRIMARY KEY,
                    applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)

            # 2. Fictional users table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS fictional_users (
                    user_id TEXT PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    role TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)

            # 3. Accounts table (balances stored in exact integer minor units - cents)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS accounts (
                    account_id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    account_name TEXT NOT NULL,
                    account_type TEXT NOT NULL,
                    balance_cents INTEGER NOT NULL CHECK (balance_cents >= 0),
                    currency TEXT NOT NULL DEFAULT 'USD',
                    daily_limit_cents INTEGER NOT NULL CHECK (daily_limit_cents >= 0),
                    is_active INTEGER NOT NULL DEFAULT 1,
                    FOREIGN KEY (user_id) REFERENCES fictional_users (user_id)
                );
            """)

            # 4. Simulated transactions ledger table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS simulated_transactions (
                    transaction_id TEXT PRIMARY KEY,
                    idempotency_key TEXT UNIQUE NOT NULL,
                    source_account_id TEXT NOT NULL,
                    destination_account_id TEXT NOT NULL,
                    amount_cents INTEGER NOT NULL CHECK (amount_cents > 0),
                    currency TEXT NOT NULL DEFAULT 'USD',
                    memo TEXT,
                    status TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (source_account_id) REFERENCES accounts (account_id),
                    FOREIGN KEY (destination_account_id) REFERENCES accounts (account_id)
                );
            """)

            # 5. Dual approval requests table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS approval_requests (
                    request_id TEXT PRIMARY KEY,
                    transaction_fingerprint TEXT UNIQUE NOT NULL,
                    source_account_id TEXT NOT NULL,
                    destination_account_id TEXT NOT NULL,
                    amount_cents INTEGER NOT NULL,
                    currency TEXT NOT NULL DEFAULT 'USD',
                    initiator_user_id TEXT NOT NULL,
                    approver_user_id TEXT,
                    status TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    approved_at TIMESTAMP,
                    FOREIGN KEY (source_account_id) REFERENCES accounts (account_id),
                    FOREIGN KEY (destination_account_id) REFERENCES accounts (account_id),
                    FOREIGN KEY (initiator_user_id) REFERENCES fictional_users (user_id)
                );
            """)

            # 6. Consumed authorization tickets (prevents replay / concurrency)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS consumed_tickets (
                    ticket_id TEXT PRIMARY KEY,
                    fingerprint TEXT UNIQUE NOT NULL,
                    consumed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    consumed_by_user_id TEXT NOT NULL
                );
            """)
            conn.execute("""
                CREATE UNIQUE INDEX IF NOT EXISTS idx_consumed_tickets_fingerprint
                ON consumed_tickets (fingerprint);
            """)

            # 7. Persistent Tamper-Evident Audit Events with Cryptographic Hash Chain
            conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_events (
                    sequence_num INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT UNIQUE NOT NULL,
                    prev_hash TEXT NOT NULL,
                    event_hash TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    principal_id TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    transaction_id TEXT,
                    details_json TEXT NOT NULL
                );
            """)

            # Mark migration 1 as applied
            conn.execute("INSERT OR IGNORE INTO schema_migrations (version) VALUES (1);")

            # Seed fictional sandbox users (INSERT OR IGNORE preserves state)
            seed_users = [
                ("USR-4401-ALICE", "alice", "CUSTOMER"),
                ("USR-8899-BOB", "bob", "CUSTOMER"),
                ("USR-9900-CHARLIE", "charlie", "APPROVER"),
                ("USR-1100-DAVE", "dave", "CUSTOMER"),
            ]
            conn.executemany(
                "INSERT OR IGNORE INTO fictional_users (user_id, username, role) VALUES (?, ?, ?);",
                seed_users,
            )

            # Seed fictional sandbox accounts
            seed_accounts = [
                ("ACC-1001-CHK", "USR-4401-ALICE", "Everyday Checking", "CHECKING", 482050, "USD", 500000, 1),
                ("ACC-2002-SAV", "USR-4401-ALICE", "High-Yield Savings", "SAVINGS", 3250000, "USD", 2500000, 1),
                ("ACC-3003-BUS", "USR-8899-BOB", "Commercial Operating", "CHECKING", 14500000, "USD", 5000000, 1),
                ("ACC-4004-CHK", "USR-1100-DAVE", "Dave Standard Checking", "CHECKING", 120000, "USD", 300000, 1),
            ]
            conn.executemany(
                """INSERT OR IGNORE INTO accounts
                   (account_id, user_id, account_name, account_type, balance_cents, currency, daily_limit_cents, is_active)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?);""",
                seed_accounts,
            )

            conn.execute("COMMIT;")
        except Exception:
            conn.execute("ROLLBACK;")
            raise


def reset_ledger_database_for_testing(db_path: str) -> None:
    """Helper for test suites to recreate an isolated, pristine testing database."""
    if os.path.exists(db_path):
        os.remove(db_path)
    init_ledger_database(db_path)
