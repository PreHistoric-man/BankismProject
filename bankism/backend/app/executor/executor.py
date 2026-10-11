"""
Single Protected Execution Gateway
"""
import sqlite3
import uuid
from datetime import datetime, timezone
from fastapi import HTTPException, status

from ..security.auth import Principal, verify_account_ownership
from ..authorization.tickets import verify_ticket_integrity
from ..schemas.requests import AuthorizationTicketModel
from ..schemas.responses import ExecutionReceipt
from ..audit.tamper_evident import append_audit_event
from ..banking.operations import get_account_by_id


def execute_transfer(
    conn: sqlite3.Connection,
    principal: Principal,
    ticket: AuthorizationTicketModel
) -> ExecutionReceipt:
    """
    Executes transfer atomically through the single protected gateway.
    Enforces replay protection, ticket signature verification, balance sufficiency,
    and append-only audit chaining.
    """
    now_iso = datetime.now(timezone.utc).isoformat()
    tx = ticket.canonical_tx

    # 1. Initiator identity check: caller must match ticket initiator
    if principal.user_id != tx.initiator_user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"PRINCIPAL_MISMATCH: Caller '{principal.user_id}' does not match ticket initiator '{tx.initiator_user_id}'."
        )

    # 2. Re-verify account ownership
    verify_account_ownership(principal, tx.source_account_id)

    # 3. Cryptographic ticket integrity verification (HMAC-SHA256)
    if not verify_ticket_integrity(ticket):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="INVALID_AUTHORIZATION_TICKET: Ticket signature verification failed or ticket expired."
        )

    # 4. Atomic execution transaction
    with conn:
        # 4a. Replay prevention: atomically insert into consumed_tickets
        try:
            conn.execute(
                "INSERT INTO consumed_tickets (ticket_id, consumed_at_utc, transaction_fingerprint, initiator_user_id) VALUES (?, ?, ?, ?);",
                (ticket.ticket_id, now_iso, ticket.fingerprint, principal.user_id)
            )
        except sqlite3.IntegrityError:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"TICKET_REPLAY_DETECTED: Ticket '{ticket.ticket_id}' has already been consumed."
            )

        # 4b. Re-verify balance sufficiency
        src_account = get_account_by_id(conn, tx.source_account_id)
        if not src_account or src_account.balance_cents < tx.amount_cents:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="INSUFFICIENT_FUNDS_AT_EXECUTION: Source account lacks required balance."
            )

        # 4c. Atomic debit and credit
        conn.execute(
            "UPDATE accounts SET balance_cents = balance_cents - ? WHERE account_id = ?;",
            (tx.amount_cents, tx.source_account_id)
        )
        conn.execute(
            "UPDATE accounts SET balance_cents = balance_cents + ? WHERE account_id = ?;",
            (tx.amount_cents, tx.destination_account_id)
        )

        # 4d. Create transaction record
        tx_id = f"tx_{uuid.uuid4().hex[:10]}"
        event_payload = {
            "tx_id": tx_id,
            "ticket_id": ticket.ticket_id,
            "source_account_id": tx.source_account_id,
            "destination_account_id": tx.destination_account_id,
            "amount_cents": tx.amount_cents,
            "initiator_user_id": principal.user_id,
        }

        # 4e. Append to tamper-evident audit log
        audit_hash = append_audit_event(
            conn=conn,
            event_id=f"ev_{uuid.uuid4().hex[:10]}",
            event_type="TRANSFER_EXECUTED",
            user_id=principal.user_id,
            payload=event_payload,
            timestamp_utc=now_iso
        )

        conn.execute(
            """INSERT INTO simulated_transactions 
            (tx_id, user_id, source_account_id, destination_account_id, amount_cents, currency, memo, status, created_at_utc, audit_event_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);""",
            (
                tx_id, principal.user_id, tx.source_account_id, tx.destination_account_id,
                tx.amount_cents, tx.currency, "Simulated transfer", "COMPLETED",
                now_iso, audit_hash
            )
        )

    return ExecutionReceipt(
        tx_id=tx_id,
        source_account_id=tx.source_account_id,
        destination_account_id=tx.destination_account_id,
        amount_dollars=tx.amount_cents / 100.0,
        amount_cents=tx.amount_cents,
        currency=tx.currency,
        audit_event_hash=audit_hash,
        executed_at_utc=now_iso
    )
