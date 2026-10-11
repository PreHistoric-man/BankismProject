"""
High-Risk Dual Approval Workflow Manager
"""
import sqlite3
import uuid
import time
from typing import Dict, Any, Optional, Tuple
from datetime import datetime, timezone, timedelta
from fastapi import HTTPException, status
from ..schemas.common import UserRole
from ..schemas.requests import CanonicalTransactionPayload, AuthorizationTicketModel
from ..schemas.responses import DualApprovalRequestInfo
from .tickets import create_authorization_ticket
from ..config import settings


def create_dual_approval_request(
    conn: sqlite3.Connection,
    initiator_user_id: str,
    src: str,
    dst: str,
    amount_cents: int,
    reason: str
) -> DualApprovalRequestInfo:
    """
    Creates a pending dual approval request for a high-risk transfer.
    """
    req_id = f"apr_{uuid.uuid4().hex[:10]}"
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(seconds=settings.dual_approval_expiry_seconds)

    now_iso = now.isoformat()
    expires_iso = expires_at.isoformat()

    conn.execute(
        """INSERT INTO dual_approval_requests 
        (request_id, initiator_user_id, source_account_id, destination_account_id, amount_cents, reason, status, approver_user_id, created_at_utc, expires_at_utc)
        VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?, ?);""",
        (req_id, initiator_user_id, src, dst, amount_cents, reason, "PENDING_DUAL_APPROVAL", now_iso, expires_iso)
    )

    return DualApprovalRequestInfo(
        request_id=req_id,
        initiator_user_id=initiator_user_id,
        source_account_id=src,
        destination_account_id=dst,
        amount_dollars=amount_cents / 100.0,
        reason=reason,
        status="PENDING_DUAL_APPROVAL",
        expires_at_utc=expires_iso
    )


def process_dual_approval(
    conn: sqlite3.Connection,
    request_id: str,
    approver_user_id: str,
    approver_role: UserRole,
    approved: bool,
    reason: str = ""
) -> Tuple[str, Optional[AuthorizationTicketModel]]:
    """
    Executes secondary sign-off.
    Enforces separation of duties: initiator cannot approve their own transfer.
    """
    cur = conn.execute(
        "SELECT request_id, initiator_user_id, source_account_id, destination_account_id, amount_cents, status, expires_at_utc FROM dual_approval_requests WHERE request_id = ?;",
        (request_id,)
    )
    req = cur.fetchone()
    if not req:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"APPROVAL_REQUEST_NOT_FOUND: Request '{request_id}' not found."
        )

    if req["status"] != "PENDING_DUAL_APPROVAL":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"INVALID_APPROVAL_STATE: Request '{request_id}' is already '{req['status']}'."
        )

    # 1. Self-approval invariant: Initiator cannot approve their own transfer
    if req["initiator_user_id"] == approver_user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="SELF_APPROVAL_PROHIBITED: Initiator cannot approve their own transfer request."
        )

    # 2. Approver role invariant
    if approver_role not in (UserRole.APPROVER, UserRole.ADMIN):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"UNAUTHORIZED_APPROVER: Role '{approver_role.value}' lacks dual-approval permissions."
        )

    # 3. Expiration check
    now = datetime.now(timezone.utc)
    try:
        exp_dt = datetime.fromisoformat(req["expires_at_utc"].replace("Z", "+00:00"))
        if now > exp_dt:
            conn.execute("UPDATE dual_approval_requests SET status = 'EXPIRED' WHERE request_id = ?;", (request_id,))
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"APPROVAL_REQUEST_EXPIRED: Request '{request_id}' has expired."
            )
    except ValueError:
        pass

    if not approved:
        conn.execute(
            "UPDATE dual_approval_requests SET status = 'REJECTED', approver_user_id = ? WHERE request_id = ?;",
            (approver_user_id, request_id)
        )
        return "REJECTED", None

    # Update status to APPROVED
    conn.execute(
        "UPDATE dual_approval_requests SET status = 'APPROVED', approver_user_id = ? WHERE request_id = ?;",
        (approver_user_id, request_id)
    )

    # Issue signed authorization ticket
    nonce = f"nonce_approved_{uuid.uuid4().hex[:10]}"
    canonical_tx = CanonicalTransactionPayload(
        transaction_nonce=nonce,
        initiator_user_id=req["initiator_user_id"],
        source_account_id=req["source_account_id"],
        destination_account_id=req["destination_account_id"],
        amount_cents=req["amount_cents"],
        currency="USD"
    )

    fingerprint = f"fp_dual_approved_{uuid.uuid4().hex[:14]}"
    watermark = f"wm_dual_{req['initiator_user_id']}"

    ticket = create_authorization_ticket(
        tx=canonical_tx,
        fingerprint=fingerprint,
        history_watermark=watermark,
        expiry_seconds=settings.ticket_expiry_seconds
    )

    return "APPROVED", ticket
