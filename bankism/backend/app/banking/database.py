"""
SQLite Database Connection and Schema Migration Manager
"""
import sqlite3
import os
from typing import Optional
from ..config import settings


SCHEMA_SQL = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS accounts (
    account_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    owner_user_id TEXT NOT NULL,
    balance_cents INTEGER NOT NULL CHECK (balance_cents >= 0),
    daily_limit_cents INTEGER NOT NULL CHECK (daily_limit_cents >= 0),
    created_at_utc TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS simulated_transactions (
    tx_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    source_account_id TEXT NOT NULL,
    destination_account_id TEXT NOT NULL,
    amount_cents INTEGER NOT NULL CHECK (amount_cents > 0),
    currency TEXT NOT NULL DEFAULT 'USD',
    memo TEXT,
    status TEXT NOT NULL,
    created_at_utc TEXT NOT NULL,
    audit_event_hash TEXT,
    FOREIGN KEY(source_account_id) REFERENCES accounts(account_id)
);

CREATE TABLE IF NOT EXISTS transfer_attempts (
    attempt_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    source_account_id TEXT NOT NULL,
    destination_account_id TEXT NOT NULL,
    amount_cents INTEGER NOT NULL,
    status TEXT NOT NULL,
    reason TEXT,
    created_at_utc TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS consumed_tickets (
    ticket_id TEXT PRIMARY KEY,
    consumed_at_utc TEXT NOT NULL,
    transaction_fingerprint TEXT NOT NULL,
    initiator_user_id TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS dual_approval_requests (
    request_id TEXT PRIMARY KEY,
    initiator_user_id TEXT NOT NULL,
    source_account_id TEXT NOT NULL,
    destination_account_id TEXT NOT NULL,
    amount_cents INTEGER NOT NULL CHECK (amount_cents > 0),
    reason TEXT NOT NULL,
    status TEXT NOT NULL,
    approver_user_id TEXT,
    created_at_utc TEXT NOT NULL,
    expires_at_utc TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tamper_evident_audit_logs (
    event_id TEXT PRIMARY KEY,
    prev_hash TEXT NOT NULL,
    event_type TEXT NOT NULL,
    user_id TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    timestamp_utc TEXT NOT NULL,
    event_hash TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS risk_assessments (
    assessment_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    source_account_id TEXT NOT NULL,
    destination_account_id TEXT NOT NULL,
    amount_cents INTEGER NOT NULL,
    currency TEXT NOT NULL DEFAULT 'USD',
    risk_score REAL NOT NULL,
    risk_level TEXT NOT NULL,
    profile_status TEXT NOT NULL,
    policy_action TEXT NOT NULL,
    factors_json TEXT NOT NULL,
    history_watermark TEXT NOT NULL,
    created_at_utc TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_transactions_user ON simulated_transactions(user_id, status);
CREATE INDEX IF NOT EXISTS idx_attempts_user ON transfer_attempts(user_id, created_at_utc);
CREATE INDEX IF NOT EXISTS idx_audit_chain ON tamper_evident_audit_logs(timestamp_utc);
CREATE INDEX IF NOT EXISTS idx_risk_user ON risk_assessments(user_id);
"""


def get_db_connection(db_path: Optional[str] = None) -> sqlite3.Connection:
    """
    Returns an isolated SQLite connection with WAL mode and row factory.
    """
    path = db_path or settings.database_path
    conn = sqlite3.connect(path, timeout=30.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db(db_path: Optional[str] = None) -> None:
    """
    Initializes tables and seeds initial fictional accounts and transactions if empty.
    """
    conn = get_db_connection(db_path)
    try:
        with conn:
            conn.executescript(SCHEMA_SQL)
            # Check if seeded
            cur = conn.execute("SELECT COUNT(*) as cnt FROM accounts;")
            row = cur.fetchone()
            if row and row["cnt"] == 0:
                _seed_initial_data(conn)
    finally:
        conn.close()


def _seed_initial_data(conn: sqlite3.Connection) -> None:
    """
    Inserts deterministic fictional accounts and historical ledger entries.
    """
    # 1. Accounts
    accounts = [
        ("ACC-1001-CHK", "Everyday Checking", "USR-4401-ALICE", 482050, 500000, "2026-10-01T00:00:00Z"),
        ("ACC-2002-SAV", "High-Yield Savings", "USR-4401-ALICE", 3250000, 2500000, "2026-10-01T00:00:00Z"),
        ("ACC-3003-BUS", "Commercial Operating", "USR-8899-BOB", 14500000, 5000000, "2026-10-01T00:00:00Z"),
        ("ACC-4004-CHK", "Standard Checking", "USR-1100-DAVE", 120000, 300000, "2026-10-01T00:00:00Z"),
    ]
    conn.executemany(
        "INSERT INTO accounts (account_id, name, owner_user_id, balance_cents, daily_limit_cents, created_at_utc) VALUES (?, ?, ?, ?, ?, ?);",
        accounts
    )

    # 2. Historical completed transactions
    # Alice: 5 established transfers (~$90-$110) to ACC-2002-SAV
    alice_txs = [
        ("tx_hist_a1", "USR-4401-ALICE", "ACC-1001-CHK", "ACC-2002-SAV", 10000, "Routine savings transfer", "COMPLETED", "2026-10-06T10:00:00Z"),
        ("tx_hist_a2", "USR-4401-ALICE", "ACC-1001-CHK", "ACC-2002-SAV", 9500, "Weekly deposit", "COMPLETED", "2026-10-07T11:00:00Z"),
        ("tx_hist_a3", "USR-4401-ALICE", "ACC-1001-CHK", "ACC-2002-SAV", 11000, "Transfer to savings", "COMPLETED", "2026-10-08T09:30:00Z"),
        ("tx_hist_a4", "USR-4401-ALICE", "ACC-1001-CHK", "ACC-2002-SAV", 10500, "Savings allocation", "COMPLETED", "2026-10-09T14:15:00Z"),
        ("tx_hist_a5", "USR-4401-ALICE", "ACC-1001-CHK", "ACC-2002-SAV", 9000, "Weekend reserve", "COMPLETED", "2026-10-10T16:45:00Z"),
    ]
    # Bob: 4 established commercial transfers (~$1,200-$1,550) to ACC-1001-CHK
    bob_txs = [
        ("tx_hist_b1", "USR-8899-BOB", "ACC-3003-BUS", "ACC-1001-CHK", 120000, "Vendor invoice 101", "COMPLETED", "2026-10-05T08:00:00Z"),
        ("tx_hist_b2", "USR-8899-BOB", "ACC-3003-BUS", "ACC-1001-CHK", 150000, "Vendor invoice 102", "COMPLETED", "2026-10-07T08:00:00Z"),
        ("tx_hist_b3", "USR-8899-BOB", "ACC-3003-BUS", "ACC-1001-CHK", 135000, "Commercial payment", "COMPLETED", "2026-10-08T15:00:00Z"),
        ("tx_hist_b4", "USR-8899-BOB", "ACC-3003-BUS", "ACC-1001-CHK", 155000, "Vendor batch", "COMPLETED", "2026-10-10T12:00:00Z"),
    ]
    # Dave: 1 completed transfer -> Cold-Start (INSUFFICIENT_HISTORY < 3)
    dave_txs = [
        ("tx_hist_d1", "USR-1100-DAVE", "ACC-4004-CHK", "ACC-1001-CHK", 4500, "Initial transfer", "COMPLETED", "2026-10-08T12:00:00Z"),
    ]

    all_txs = alice_txs + bob_txs + dave_txs
    conn.executemany(
        "INSERT INTO simulated_transactions (tx_id, user_id, source_account_id, destination_account_id, amount_cents, memo, status, created_at_utc) VALUES (?, ?, ?, ?, ?, ?, ?, ?);",
        all_txs
    )
