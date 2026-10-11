"""Single Protected Execution Boundary for simulated financial transfers."""

import sqlite3
import uuid
from typing import Optional
from pydantic import BaseModel, Field

from ..audit.tamper_evident import get_tamper_evident_audit_store
from ..authorization.tickets import AuthorizationTicket, verify_ticket_integrity
from ..config import get_settings
from ..ledger.models import cents_to_dollars
from ..ledger.operations import (
    execute_atomic_ledger_transfer,
    get_account_by_id_db,
)
from ..profiling.engine import get_behavioral_risk_engine
from ..schemas.auth import AuthenticatedPrincipal
from ..schemas.profiling import BehavioralRiskLevel
from ..security.auth import authorize_account_ownership


class ExecutionReceipt(BaseModel):
    """Immutable proof of completed simulated transaction."""

    transaction_id: str
    idempotency_key: str
    source_account_id: str
    destination_account_id: str
    amount_cents: int
    amount_dollars: float
    currency: str
    memo: Optional[str] = None
    status: str = "COMPLETED"
    consumed_ticket_id: str
    audit_event_hash: str
    executed_at: str


class SimulatedTransactionExecutor:
    """The sole protected execution gateway for simulated banking operations.

    CRITICAL SECURITY INVARIANTS:
    1. NEVER accepts an LLM classification or client permission flag as authorization.
    2. Requires an unconsumed, unexpired, unforgeable AuthorizationTicket signed server-side.
    3. Re-checks account state and ownership immediately before debit.
    4. Consumes the ticket atomically to prevent replay and double-spending.
    5. Dispatches atomic debit/credit updates via SQLite ledger.
    6. Appends an immutable record to the tamper-evident cryptographic hash chain.
    """

    def __init__(self, secret_key: Optional[str] = None):
        self.secret_key = secret_key or get_settings().hmac_secret
        self.audit_store = get_tamper_evident_audit_store()

    def execute_transfer(
        self,
        conn: sqlite3.Connection,
        principal: AuthenticatedPrincipal,
        ticket: AuthorizationTicket,
        idempotency_key: Optional[str] = None,
    ) -> ExecutionReceipt:
        """Execute a simulated transfer against the SQLite ledger.

        Enforces:
        - Cryptographic ticket verification (HMAC and fingerprint recomputation).
        - Single-use ticket consumption (replay prevention).
        - Principal ownership and account state re-verification under lock.
        - Atomic execution in SQLite.
        """
        # 1. Cryptographically verify the ticket
        verify_ticket_integrity(ticket, self.secret_key)

        tx = ticket.canonical_tx

        # 2. Verify principal match
        if principal.user_id != tx.initiator_user_id:
            raise ValueError(
                f"Principal mismatch: Authenticated user '{principal.user_id}' does not match "
                f"ticket initiator '{tx.initiator_user_id}'."
            )

        # 3. Verify account ownership
        authorize_account_ownership(principal, tx.source_account_id)

        # Use transaction nonce or caller's key as idempotency key
        idem_key = idempotency_key or f"idem_{tx.transaction_nonce}"
        tx_id = f"tx_{uuid.uuid4().hex[:14]}"

        # Begin atomic transaction block
        conn.execute("BEGIN IMMEDIATE;")
        try:
            # 4. Atomically consume the ticket (Replay protection)
            # Check if ticket_id OR fingerprint was already consumed
            cur = conn.execute(
                "SELECT ticket_id, fingerprint FROM consumed_tickets WHERE ticket_id = ? OR fingerprint = ?;",
                (ticket.ticket_id, ticket.fingerprint),
            )
            if cur.fetchone():
                raise ValueError(
                    f"Replay attack detected: Ticket '{ticket.ticket_id}' or transaction fingerprint '{ticket.fingerprint}' has already been consumed."
                )

            try:
                conn.execute(
                    """INSERT INTO consumed_tickets (ticket_id, fingerprint, consumed_by_user_id)
                       VALUES (?, ?, ?);""",
                    (ticket.ticket_id, ticket.fingerprint, principal.user_id),
                )
            except sqlite3.IntegrityError:
                raise ValueError(
                    f"Replay attack detected: Ticket '{ticket.ticket_id}' or transaction fingerprint '{ticket.fingerprint}' has already been consumed."
                )

            # 5. Re-check current account state under write lock
            src = get_account_by_id_db(conn, tx.source_account_id)
            if not src or not src.is_active:
                raise ValueError(f"Source account '{tx.source_account_id}' is invalid or inactive.")
            if src.balance_cents < tx.amount_cents:
                raise ValueError(
                    f"Insufficient funds: Available balance is {src.balance_cents} cents, "
                    f"requested {tx.amount_cents} cents."
                )

            # 5b. Phase 3 TOCTOU (Time-of-Check to Time-of-Use) Behavioral Risk Verification
            risk_engine = get_behavioral_risk_engine()
            prior_assessment = risk_engine.get_assessment_by_fingerprint(conn, ticket.fingerprint)
            is_dual_approved_ticket = tx.transaction_nonce.startswith("nonce_apr_")
            if prior_assessment is not None:
                if prior_assessment.final_outcome == "PENDING_DUAL_APPROVAL" and not is_dual_approved_ticket:
                    raise ValueError(
                        "Execution rejected: Transaction requires secondary dual approval before execution."
                    )
                if getattr(get_settings(), "enable_toctou_watermark_check", True) and not is_dual_approved_ticket:
                    current_stats = risk_engine.get_historical_stats(
                        conn,
                        user_id=principal.user_id,
                        account_id=tx.source_account_id,
                    )
                    if (
                        prior_assessment.history_watermark
                        and current_stats.history_watermark != prior_assessment.history_watermark
                    ):
                        reassessed = risk_engine.assess_transaction_risk(
                            conn=conn,
                            user_id=principal.user_id,
                            source_account_id=tx.source_account_id,
                            destination_account_id=tx.destination_account_id,
                            amount_cents=tx.amount_cents,
                            transaction_fingerprint=ticket.fingerprint,
                            currency=tx.currency,
                            persist=False,
                        )
                        if reassessed.risk_level in (BehavioralRiskLevel.HIGH, BehavioralRiskLevel.CRITICAL):
                            risk_engine.update_assessment_outcome(
                                conn,
                                assessment_id=prior_assessment.assessment_id,
                                final_outcome="INVALIDATED_TOCTOU_DRIFT",
                            )
                            raise ValueError(
                                "TOCTOU security violation: Account transaction history changed materially since "
                                f"authorization (reassessed risk={reassessed.risk_level.value}, score={reassessed.risk_score}); "
                                "stale single-authorization ticket invalidated."
                            )

            # 6. Execute atomic debit/credit in ledger
            tx_record = execute_atomic_ledger_transfer(
                conn=conn,
                transaction_id=tx_id,
                idempotency_key=idem_key,
                source_account_id=tx.source_account_id,
                destination_account_id=tx.destination_account_id,
                amount_cents=tx.amount_cents,
                currency=tx.currency,
                memo=tx.memo,
            )

            if prior_assessment is not None:
                risk_engine.update_assessment_outcome(
                    conn,
                    assessment_id=prior_assessment.assessment_id,
                    final_outcome="COMPLETED",
                )
            risk_engine.record_transfer_attempt(
                conn=conn,
                user_id=principal.user_id,
                source_account_id=tx.source_account_id,
                destination_account_id=tx.destination_account_id,
                amount_cents=tx.amount_cents,
                outcome="COMPLETED",
                currency=tx.currency,
                reason=f"Executed tx_id={tx_id}",
                assessment_id=prior_assessment.assessment_id if prior_assessment else None,
            )

            # 7. Record to tamper-evident audit ledger
            event_hash = self.audit_store.record_audit_event(
                conn=conn,
                event_type="TRANSACTION_EXECUTED",
                principal_id=principal.user_id,
                decision="EXECUTE_APPROVED",
                transaction_id=tx_id,
                details={
                    "source_account_id": tx.source_account_id,
                    "destination_account_id": tx.destination_account_id,
                    "amount_cents": tx.amount_cents,
                    "currency": tx.currency,
                    "ticket_id": ticket.ticket_id,
                    "fingerprint": ticket.fingerprint,
                    "idempotency_key": idem_key,
                },
            )

            conn.execute("COMMIT;")

            return ExecutionReceipt(
                transaction_id=tx_id,
                idempotency_key=idem_key,
                source_account_id=tx.source_account_id,
                destination_account_id=tx.destination_account_id,
                amount_cents=tx.amount_cents,
                amount_dollars=cents_to_dollars(tx.amount_cents),
                currency=tx.currency,
                memo=tx.memo,
                status="COMPLETED",
                consumed_ticket_id=ticket.ticket_id,
                audit_event_hash=event_hash,
                executed_at=tx_record.created_at,
            )

        except Exception:
            conn.execute("ROLLBACK;")
            raise


_executor_instance: Optional[SimulatedTransactionExecutor] = None


def get_transaction_executor() -> SimulatedTransactionExecutor:
    global _executor_instance
    if _executor_instance is None:
        _executor_instance = SimulatedTransactionExecutor()
    return _executor_instance
