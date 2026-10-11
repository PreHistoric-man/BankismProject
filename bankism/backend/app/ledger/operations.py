"""Atomic SQLite ledger operations with strict balance and idempotency constraints."""

import sqlite3
from typing import List, Optional
from .models import AccountRecord, TransactionRecord, TransactionStatus


class LedgerError(Exception):
    """Base error for ledger operations."""
    pass


class InsufficientFundsError(LedgerError):
    """Raised when account balance is less than transfer amount."""
    pass


class InactiveAccountError(LedgerError):
    """Raised when source or destination account is inactive."""
    pass


class AccountNotFoundError(LedgerError):
    """Raised when account does not exist."""
    pass


class DuplicateIdempotencyKeyError(LedgerError):
    """Raised when an idempotency key has already been consumed."""
    pass


class InvalidCurrencyError(LedgerError):
    """Raised when currency does not match account currency."""
    pass


def get_account_by_id_db(conn: sqlite3.Connection, account_id: str) -> Optional[AccountRecord]:
    """Retrieve account record by account_id."""
    cursor = conn.execute(
        """SELECT account_id, user_id, account_name, account_type,
                  balance_cents, currency, daily_limit_cents, is_active
           FROM accounts WHERE account_id = ?;""",
        (account_id,),
    )
    row = cursor.fetchone()
    if not row:
        return None
    return AccountRecord(
        account_id=row["account_id"],
        user_id=row["user_id"],
        account_name=row["account_name"],
        account_type=row["account_type"],
        balance_cents=row["balance_cents"],
        currency=row["currency"],
        daily_limit_cents=row["daily_limit_cents"],
        is_active=bool(row["is_active"]),
    )


def get_account_balance_cents(conn: sqlite3.Connection, account_id: str) -> int:
    """Retrieve exact balance in integer cents."""
    acc = get_account_by_id_db(conn, account_id)
    if not acc:
        raise AccountNotFoundError(f"Account '{account_id}' does not exist.")
    return acc.balance_cents


def get_account_transactions(
    conn: sqlite3.Connection,
    account_id: str,
    limit: int = 50,
) -> List[TransactionRecord]:
    """Retrieve transaction history for an account."""
    cursor = conn.execute(
        """SELECT transaction_id, idempotency_key, source_account_id,
                  destination_account_id, amount_cents, currency, memo, status, created_at
           FROM simulated_transactions
           WHERE source_account_id = ? OR destination_account_id = ?
           ORDER BY created_at DESC
           LIMIT ?;""",
        (account_id, account_id, limit),
    )
    records = []
    for row in cursor.fetchall():
        records.append(
            TransactionRecord(
                transaction_id=row["transaction_id"],
                idempotency_key=row["idempotency_key"],
                source_account_id=row["source_account_id"],
                destination_account_id=row["destination_account_id"],
                amount_cents=row["amount_cents"],
                currency=row["currency"],
                memo=row["memo"],
                status=TransactionStatus(row["status"]),
                created_at=str(row["created_at"]),
            )
        )
    return records


def execute_atomic_ledger_transfer(
    conn: sqlite3.Connection,
    transaction_id: str,
    idempotency_key: str,
    source_account_id: str,
    destination_account_id: str,
    amount_cents: int,
    currency: str = "USD",
    memo: Optional[str] = None,
) -> TransactionRecord:
    """Execute an atomic debit-credit transfer within a SQLite transaction.

    Enforces:
    1. Positive amount
    2. Idempotency key uniqueness
    3. Source and destination exist and active
    4. Sufficient balance constraint: atomic decrement `balance_cents = balance_cents - ? WHERE balance_cents >= ?`
    5. Atomic credit to destination
    6. Complete rollback if any step fails.
    """
    if amount_cents <= 0:
        raise ValueError("Transfer amount must be strictly greater than zero.")

    if source_account_id == destination_account_id:
        raise ValueError("Source and destination accounts must be distinct.")

    # Check for existing idempotency key
    cursor = conn.execute(
        "SELECT transaction_id, status FROM simulated_transactions WHERE idempotency_key = ?;",
        (idempotency_key,),
    )
    existing = cursor.fetchone()
    if existing:
        raise DuplicateIdempotencyKeyError(
            f"Idempotency key '{idempotency_key}' was already used for transaction '{existing['transaction_id']}'."
        )

    # Validate accounts
    src = get_account_by_id_db(conn, source_account_id)
    if not src:
        raise AccountNotFoundError(f"Source account '{source_account_id}' does not exist.")
    if not src.is_active:
        raise InactiveAccountError(f"Source account '{source_account_id}' is inactive.")
    if src.currency != currency:
        raise InvalidCurrencyError(
            f"Source account currency '{src.currency}' does not match requested currency '{currency}'."
        )

    dst = get_account_by_id_db(conn, destination_account_id)
    if not dst:
        raise AccountNotFoundError(f"Destination account '{destination_account_id}' does not exist.")
    if not dst.is_active:
        raise InactiveAccountError(f"Destination account '{destination_account_id}' is inactive.")
    if dst.currency != currency:
        raise InvalidCurrencyError(
            f"Destination account currency '{dst.currency}' does not match requested currency '{currency}'."
        )

    # Atomic debit with sufficiency check
    cur = conn.execute(
        """UPDATE accounts
           SET balance_cents = balance_cents - ?
           WHERE account_id = ? AND balance_cents >= ? AND is_active = 1;""",
        (amount_cents, source_account_id, amount_cents),
    )
    if cur.rowcount == 0:
        raise InsufficientFundsError(
            f"Source account '{source_account_id}' has insufficient funds for transfer of {amount_cents} cents."
        )

    # Atomic credit
    conn.execute(
        """UPDATE accounts
           SET balance_cents = balance_cents + ?
           WHERE account_id = ? AND is_active = 1;""",
        (amount_cents, destination_account_id),
    )

    # Insert transaction record
    conn.execute(
        """INSERT INTO simulated_transactions
           (transaction_id, idempotency_key, source_account_id, destination_account_id,
            amount_cents, currency, memo, status)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?);""",
        (
            transaction_id,
            idempotency_key,
            source_account_id,
            destination_account_id,
            amount_cents,
            currency,
            memo,
            TransactionStatus.COMPLETED.value,
        ),
    )

    return TransactionRecord(
        transaction_id=transaction_id,
        idempotency_key=idempotency_key,
        source_account_id=source_account_id,
        destination_account_id=destination_account_id,
        amount_cents=amount_cents,
        currency=currency,
        memo=memo,
        status=TransactionStatus.COMPLETED,
        created_at="now",
    )
