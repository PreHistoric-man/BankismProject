"""Dual approval workflow manager for high-risk simulated transactions."""

import sqlite3
import time
import uuid
from typing import Dict, Optional
from ..config import get_settings
from ..schemas.auth import AuthenticatedPrincipal
from ..security.auth import authorize_dual_approver
from .tickets import (
    AuthorizationTicket,
    CanonicalTransaction,
    compute_canonical_fingerprint,
    create_authorization_ticket,
)


class DualApprovalManager:
    """Manages multi-signature dual approvals for transactions exceeding high-risk threshold."""

    def __init__(self, high_risk_threshold_cents: int = 1000000, expiry_seconds: int = 3600):
        self.high_risk_threshold_cents = high_risk_threshold_cents
        self.expiry_seconds = expiry_seconds

    def requires_dual_approval(self, amount_cents: int) -> bool:
        """Check if amount meets or exceeds the high-risk dual approval policy threshold."""
        return amount_cents >= self.high_risk_threshold_cents

    def create_approval_request(
        self,
        conn: sqlite3.Connection,
        tx: CanonicalTransaction,
    ) -> Dict:
        """Create a pending dual-approval record bound to the transaction fingerprint."""
        request_id = f"apr_{uuid.uuid4().hex[:12]}"
        fingerprint = compute_canonical_fingerprint(tx)
        now = time.time()
        expires_at = now + self.expiry_seconds

        conn.execute(
            """INSERT INTO approval_requests
               (request_id, transaction_fingerprint, source_account_id, destination_account_id,
                amount_cents, currency, initiator_user_id, status, expires_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, 'PENDING', ?);""",
            (
                request_id,
                fingerprint,
                tx.source_account_id,
                tx.destination_account_id,
                tx.amount_cents,
                tx.currency,
                tx.initiator_user_id,
                str(int(expires_at)),
            ),
        )

        return {
            "request_id": request_id,
            "fingerprint": fingerprint,
            "status": "PENDING_DUAL_APPROVAL",
            "expires_at": int(expires_at),
            "initiator_user_id": tx.initiator_user_id,
            "amount_cents": tx.amount_cents,
        }

    def get_approval_request(self, conn: sqlite3.Connection, request_id: str) -> Optional[Dict]:
        """Fetch approval request row."""
        cursor = conn.execute(
            """SELECT request_id, transaction_fingerprint, source_account_id,
                      destination_account_id, amount_cents, currency, initiator_user_id,
                      approver_user_id, status, expires_at, created_at, approved_at
               FROM approval_requests WHERE request_id = ?;""",
            (request_id,),
        )
        row = cursor.fetchone()
        if not row:
            return None
        return dict(row)

    def approve_transaction(
        self,
        conn: sqlite3.Connection,
        request_id: str,
        approver: AuthenticatedPrincipal,
        secret_key: str,
    ) -> AuthorizationTicket:
        """Submit secondary authorization for a pending high-risk transaction.

        Enforces:
        1. Approver possesses APPROVER permissions.
        2. Approver is distinct from the initiator.
        3. Request exists and is PENDING.
        4. Request has not expired.
        5. Atomically transitions to APPROVED and issues the AuthorizationTicket.
        """
        row = self.get_approval_request(conn, request_id)
        if not row:
            raise ValueError(f"Approval request '{request_id}' not found.")

        # 1. Enforce distinct approver authority
        authorize_dual_approver(approver, row["initiator_user_id"])

        # 2. Check status
        if row["status"] != "PENDING":
            raise ValueError(f"Approval request '{request_id}' is not in PENDING status (current: {row['status']}).")

        conn.execute("BEGIN IMMEDIATE;")
        try:
            # 3. Check expiry
            now = time.time()
            if now > float(row["expires_at"]):
                conn.execute("UPDATE approval_requests SET status = 'EXPIRED' WHERE request_id = ?;", (request_id,))
                conn.execute("COMMIT;")
                raise ValueError(f"Approval request '{request_id}' has expired.")

            # 4. Atomically transition to APPROVED
            cur = conn.execute(
                """UPDATE approval_requests
                   SET status = 'APPROVED', approver_user_id = ?, approved_at = CURRENT_TIMESTAMP
                   WHERE request_id = ? AND status = 'PENDING';""",
                (approver.user_id, request_id),
            )
            if cur.rowcount == 0:
                conn.execute("ROLLBACK;")
                raise ValueError(
                    f"Approval request '{request_id}' could not be transitioned to APPROVED (conflict or already approved)."
                )

            conn.execute("COMMIT;")
        except Exception:
            try:
                conn.execute("ROLLBACK;")
            except Exception:
                pass
            raise

        # 5. Build canonical transaction and issue signed ticket
        canonical_tx = CanonicalTransaction(
            transaction_nonce=f"nonce_{request_id}",
            initiator_user_id=row["initiator_user_id"],
            source_account_id=row["source_account_id"],
            destination_account_id=row["destination_account_id"],
            amount_cents=row["amount_cents"],
            currency=row["currency"],
            memo="Dual-Approved High-Risk Transfer",
        )

        settings = get_settings()
        return create_authorization_ticket(
            tx=canonical_tx,
            secret_key=secret_key,
            lifetime_seconds=settings.ticket_expiry_seconds,
        )


_dual_approval_manager: Optional[DualApprovalManager] = None


def get_dual_approval_manager() -> DualApprovalManager:
    global _dual_approval_manager
    if _dual_approval_manager is None:
        settings = get_settings()
        threshold_cents = int(settings.high_risk_dual_approval_threshold * 100)
        _dual_approval_manager = DualApprovalManager(
            high_risk_threshold_cents=threshold_cents,
            expiry_seconds=settings.dual_approval_expiry_seconds,
        )
    return _dual_approval_manager
