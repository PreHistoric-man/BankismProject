"""
Transfer Preparation & Authorization Service
"""
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, Tuple
from fastapi import HTTPException, status

from ..security.auth import Principal, verify_account_ownership
from ..security.sanitization import sanitize_input
from ..security.detector import detect_threats
from ..policies.engine import evaluate_firewall_policies
from ..risk.profiling import assess_transaction_risk
from ..banking.models import dollars_to_cents
from ..banking.operations import get_account_by_id, record_transfer_attempt
from ..schemas.requests import CanonicalTransactionPayload, TransferPrepareRequest
from ..schemas.responses import TransferPrepareResponse, BehavioralAssessmentResponse
from ..schemas.common import Verdict
from .tickets import create_authorization_ticket
from .dual_approval import create_dual_approval_request
from ..config import settings


def prepare_transfer_authorization(
    conn: sqlite3.Connection,
    principal: Principal,
    req: TransferPrepareRequest
) -> TransferPrepareResponse:
    """
    Orchestrates transfer preparation across ownership, balance, firewall, and behavioral risk gates.
    """
    now_iso = datetime.now(timezone.utc).isoformat()
    amount_cents = dollars_to_cents(req.amount)

    # 1. Ownership validation
    verify_account_ownership(principal, req.source_account_id)

    if req.source_account_id == req.destination_account_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="VALIDATION_REJECTED: Source and destination accounts must be distinct."
        )

    # 2. Account existence & ledger balance sufficiency
    src_account = get_account_by_id(conn, req.source_account_id)
    if not src_account:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"SOURCE_ACCOUNT_NOT_FOUND: Account '{req.source_account_id}' does not exist."
        )

    dst_account = get_account_by_id(conn, req.destination_account_id)
    if not dst_account:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"DESTINATION_ACCOUNT_NOT_FOUND: Account '{req.destination_account_id}' does not exist."
        )

    if amount_cents > src_account.balance_cents:
        record_transfer_attempt(
            conn, f"att_{uuid.uuid4().hex[:8]}", principal.user_id,
            req.source_account_id, req.destination_account_id,
            amount_cents, "REJECTED_INSUFFICIENT_FUNDS",
            f"Requested ${req.amount:,.2f} exceeds balance ${src_account.balance_dollars:,.2f}",
            now_iso
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"INSUFFICIENT_FUNDS: Requested ${req.amount:,.2f} exceeds available balance (${src_account.balance_dollars:,.2f}). Low behavioral risk cannot bypass ledger sufficiency."
        )

    # 3. AI Security Firewall Inspection
    prompt_to_check = req.prompt or f"Transfer ${req.amount:.2f} from {req.source_account_id} to {req.destination_account_id}"
    sanitized = sanitize_input(prompt_to_check)
    threats, primary_threat, risk_level, fw_score = detect_threats(
        raw_prompt=prompt_to_check,
        sanitized_prompt=sanitized,
        action="TRANSFER_FUNDS",
        memo=req.memo or ""
    )
    fw_verdict, violations, fw_reasons, requires_step_up = evaluate_firewall_policies(
        threats=threats,
        amount=req.amount,
        action="TRANSFER_FUNDS"
    )

    # 4. Behavioral Risk Intelligence Assessment
    behavioral_assessment = assess_transaction_risk(
        conn=conn,
        user_id=principal.user_id,
        username=principal.username,
        src=req.source_account_id,
        dst=req.destination_account_id,
        amount_cents=amount_cents,
        fw_verdict=fw_verdict
    )

    # 5. Golden Security Rules:
    # Rule A: Firewall BLOCK always halts authorization immediately fail-closed
    if fw_verdict == Verdict.BLOCK:
        record_transfer_attempt(
            conn, f"att_{uuid.uuid4().hex[:8]}", principal.user_id,
            req.source_account_id, req.destination_account_id,
            amount_cents, "BLOCKED_FIREWALL",
            "; ".join(fw_reasons),
            now_iso
        )
        conn.commit()
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"FIREWALL_BLOCKED: {'; '.join(fw_reasons)}. Golden Rule #2: Clean behavioral history never overrides Firewall BLOCK."
        )

    # Rule B: High amount (>= $10k), Firewall REVIEW, or Behavioral Risk HIGH/CRITICAL (score >= 50)
    # mandates Dual Approval escalation
    if (
        req.amount >= settings.high_amount_threshold
        or fw_verdict == Verdict.REVIEW
        or behavioral_assessment.risk_score >= settings.behavioral_risk_high_threshold
    ):
        escalation_reason = (
            f"Amount ${req.amount:,.2f} meets or exceeds ${settings.high_amount_threshold:,.2f} threshold"
            if req.amount >= settings.high_amount_threshold
            else (
                f"Firewall supervisory review: {'; '.join(fw_reasons)}"
                if fw_verdict == Verdict.REVIEW
                else f"Behavioral Risk Escalation ({behavioral_assessment.risk_level.value} - Score {behavioral_assessment.risk_score:.1f}/100: {behavioral_assessment.policy_action.value})"
            )
        )

        approval_info = create_dual_approval_request(
            conn=conn,
            initiator_user_id=principal.user_id,
            src=req.source_account_id,
            dst=req.destination_account_id,
            amount_cents=amount_cents,
            reason=escalation_reason
        )

        record_transfer_attempt(
            conn, f"att_{uuid.uuid4().hex[:8]}", principal.user_id,
            req.source_account_id, req.destination_account_id,
            amount_cents, "PENDING_DUAL_APPROVAL",
            escalation_reason,
            now_iso
        )
        conn.commit()

        return TransferPrepareResponse(
            status="PENDING_DUAL_APPROVAL",
            ticket=None,
            dual_approval_request=approval_info,
            risk_assessment=behavioral_assessment,
            reasons=[escalation_reason]
        )

    # Rule C: Issue single authorization ticket bound to canonical transaction
    nonce = f"nonce_{uuid.uuid4().hex[:10]}"
    canonical_tx = CanonicalTransactionPayload(
        transaction_nonce=nonce,
        initiator_user_id=principal.user_id,
        source_account_id=req.source_account_id,
        destination_account_id=req.destination_account_id,
        amount_cents=amount_cents,
        currency="USD"
    )

    ticket = create_authorization_ticket(
        tx=canonical_tx,
        fingerprint=behavioral_assessment.transaction_fingerprint,
        history_watermark=behavioral_assessment.history_watermark,
        expiry_seconds=settings.ticket_expiry_seconds
    )

    record_transfer_attempt(
        conn, f"att_{uuid.uuid4().hex[:8]}", principal.user_id,
        req.source_account_id, req.destination_account_id,
        amount_cents, "AUTHORIZED",
        "Authorization ticket issued successfully",
        now_iso
    )

    return TransferPrepareResponse(
        status="AUTHORIZED",
        ticket=ticket.model_dump(),
        dual_approval_request=None,
        risk_assessment=behavioral_assessment,
        reasons=["Request approved within standard limits; authorization ticket issued"]
    )
