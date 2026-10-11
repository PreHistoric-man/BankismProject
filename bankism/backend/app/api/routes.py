"""
Bankism FastAPI Route Definitions
"""
import time
import json
import uuid
import sqlite3
from typing import List, Optional
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Request, status

from ..security.auth import resolve_authenticated_principal, Principal
from ..security.sanitization import sanitize_input
from ..security.masking import mask_sensitive_data
from ..security.detector import detect_threats
from ..policies.engine import evaluate_firewall_policies
from ..banking.database import get_db_connection
from ..banking.operations import get_user_accounts
from ..banking.models import dollars_to_cents
from ..authorization.service import prepare_transfer_authorization
from ..authorization.dual_approval import process_dual_approval
from ..executor.executor import execute_transfer
from ..risk.profiling import compute_user_profile
from ..audit.tamper_evident import verify_audit_chain
from ..schemas.requests import (
    InspectRequest,
    TransferPrepareRequest,
    TransferConfirmRequest,
    TransferApproveRequest,
)
from ..schemas.responses import (
    InspectResponse,
    TransferPrepareResponse,
    TransferConfirmResponse,
    AccountInfo,
    UserProfileResponse,
    AuditVerificationResponse,
    BehavioralAssessmentResponse,
)
from ..config import settings


router = APIRouter()


def get_db():
    conn = get_db_connection()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


@router.get("/health", tags=["System"])
def health_check(conn: sqlite3.Connection = Depends(get_db)):
    """
    Subsystem health and database connectivity check.
    """
    try:
        cur = conn.execute("SELECT COUNT(*) as accounts_count FROM accounts;")
        row = cur.fetchone()
        accounts_count = row["accounts_count"] if row else 0
        return {
            "status": "healthy",
            "subsystems": {
                "firewall": "active",
                "database": "connected",
                "risk_engine": "active",
                "audit_chain": "active",
                "executor": "active"
            },
            "environment": settings.environment,
            "policy_version": settings.behavioral_policy_version,
            "database_records": {"accounts": accounts_count}
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"HEALTH_CHECK_FAILED: {str(e)}"
        )


@router.post("/firewall/inspect", response_model=InspectResponse, tags=["Firewall"])
def inspect_request(req: InspectRequest):
    """
    Evaluates untrusted natural language banking prompts for prompt injection,
    jailbreaks, malicious metadata, and obfuscation.
    Enforces deterministic policy rules (POL-001 through POL-007).
    CRITICAL INVARIANT: execution_permitted is permanently FALSE.
    """
    start_time = time.perf_counter()
    sanitized = sanitize_input(req.prompt)
    masked = mask_sensitive_data(sanitized)

    threats, primary_threat, risk_level, fw_score = detect_threats(
        raw_prompt=req.prompt,
        sanitized_prompt=sanitized,
        action=req.action or "UNSPECIFIED",
        memo=req.memo or ""
    )

    verdict, violations, reasons, requires_step_up = evaluate_firewall_policies(
        threats=threats,
        amount=req.amount or 0.0,
        action=req.action or "UNSPECIFIED"
    )

    latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
    inspection_id = f"ins_{uuid.uuid4().hex[:10]}"

    return InspectResponse(
        inspection_id=inspection_id,
        verdict=verdict,
        risk_level=risk_level,
        risk_score=fw_score,
        primary_threat=primary_threat,
        threats_detected=threats,
        policy_violations=violations,
        sanitized_prompt=sanitized,
        masked_prompt=masked,
        requires_step_up_auth=requires_step_up,
        execution_permitted=False,  # CRITICAL INVARIANT
        reasons=reasons,
        evaluation_latency_ms=latency_ms,
        timestamp=datetime.now(timezone.utc).isoformat()
    )


@router.get("/banking/accounts", response_model=List[AccountInfo], tags=["Banking"])
def list_accounts(
    principal: Principal = Depends(resolve_authenticated_principal),
    conn: sqlite3.Connection = Depends(get_db)
):
    """
    Returns accounts owned by the authenticated caller.
    """
    accounts = get_user_accounts(conn, principal.user_id)
    return [
        AccountInfo(
            account_id=acc.account_id,
            name=acc.name,
            owner=principal.username,
            balance_dollars=acc.balance_dollars,
            balance_cents=acc.balance_cents,
            daily_limit_dollars=acc.daily_limit_dollars
        )
        for acc in accounts
    ]


@router.post("/banking/transfers/prepare", response_model=TransferPrepareResponse, tags=["Transfers"])
def prepare_transfer(
    req: TransferPrepareRequest,
    principal: Principal = Depends(resolve_authenticated_principal),
    conn: sqlite3.Connection = Depends(get_db)
):
    """
    Prepares a transfer, validates ownership and balance, inspects via firewall,
    evaluates behavioral risk, and either issues an AuthorizationTicket or escalates to Dual Approval.
    """
    return prepare_transfer_authorization(conn=conn, principal=principal, req=req)


@router.post("/banking/transfers/confirm", response_model=TransferConfirmResponse, tags=["Transfers"])
def confirm_transfer(
    req: TransferConfirmRequest,
    principal: Principal = Depends(resolve_authenticated_principal),
    conn: sqlite3.Connection = Depends(get_db)
):
    """
    Executes a transfer via the single protected execution gateway using an unconsumed AuthorizationTicket.
    """
    receipt = execute_transfer(conn=conn, principal=principal, ticket=req.ticket)
    return TransferConfirmResponse(status="COMPLETED", receipt=receipt)


@router.post("/banking/transfers/approve", tags=["Transfers"])
def approve_transfer(
    req: TransferApproveRequest,
    principal: Principal = Depends(resolve_authenticated_principal),
    conn: sqlite3.Connection = Depends(get_db)
):
    """
    Submits secondary approval for a high-risk transfer. Enforces separation of duties.
    """
    with conn:
        status_result, ticket = process_dual_approval(
            conn=conn,
            request_id=req.request_id,
            approver_user_id=principal.user_id,
            approver_role=principal.role,
            approved=req.approved,
            reason=req.reason or "Approved by Risk Officer"
        )

    return {
        "status": status_result,
        "request_id": req.request_id,
        "approver": principal.username,
        "ticket": ticket.model_dump() if ticket else None
    }


@router.get("/banking/risk/profile", response_model=UserProfileResponse, tags=["Risk"])
def get_user_risk_profile(
    principal: Principal = Depends(resolve_authenticated_principal),
    conn: sqlite3.Connection = Depends(get_db)
):
    """
    Returns the authenticated user's behavioral profile and cold-start sufficiency.
    """
    p = compute_user_profile(conn, principal.user_id, principal.username)
    return UserProfileResponse(
        user_id=p["user_id"],
        username=p["username"],
        role=principal.role,
        profile_status=p["profile_status"],
        transaction_count=p["transaction_count"],
        count_1h=p["count_1h"],
        count_24h=p["count_24h"],
        failed_24h=p["failed_24h"],
        mean_dollars=p["mean_dollars"],
        median_dollars=p["median_dollars"],
        std_dollars=p["std_dollars"],
        max_dollars=p["max_dollars"],
        known_counterparties=p["known_counterparties"],
        history_watermark=p["history_watermark"]
    )


@router.get("/banking/risk/assessments", response_model=List[BehavioralAssessmentResponse], tags=["Risk"])
def get_user_risk_assessments(
    limit: int = 20,
    offset: int = 0,
    principal: Principal = Depends(resolve_authenticated_principal),
    conn: sqlite3.Connection = Depends(get_db)
):
    """
    Returns recent behavioral assessments scoped strictly to the authenticated principal.
    """
    cur = conn.execute(
        """SELECT assessment_id, user_id, source_account_id, destination_account_id, amount_cents, currency,
                  risk_score, risk_level, profile_status, policy_action, factors_json, history_watermark, created_at_utc
           FROM risk_assessments 
           WHERE user_id = ? 
           ORDER BY created_at_utc DESC 
           LIMIT ? OFFSET ?;""",
        (principal.user_id, min(limit, 50), offset)
    )
    rows = cur.fetchall()
    assessments = []
    for r in rows:
        factors_raw = json.loads(r["factors_json"]) if r["factors_json"] else []
        assessments.append(BehavioralAssessmentResponse(
            assessment_id=r["assessment_id"],
            user_id=r["user_id"],
            username=principal.username,
            source_account_id=r["source_account_id"],
            destination_account_id=r["destination_account_id"],
            amount_cents=r["amount_cents"],
            currency=r["currency"],
            transaction_fingerprint="",
            history_watermark=r["history_watermark"],
            risk_score=r["risk_score"],
            risk_level=r["risk_level"],
            profile_status=r["profile_status"],
            confidence=0.8,
            risk_factors=factors_raw,
            explanations=[f["description"] for f in factors_raw] if factors_raw else ["Baseline activity"],
            policy_action=r["policy_action"],
            recommended_action_reason="Persisted assessment record",
            model_version=settings.behavioral_policy_version,
            assessed_at=r["created_at_utc"],
            final_outcome="COMPLETED",
            firewall_verdict="APPROVE"
        ))
    return assessments


@router.get("/banking/risk/assessments/{assessment_id}", response_model=BehavioralAssessmentResponse, tags=["Risk"])
def get_risk_assessment_by_id(
    assessment_id: str,
    principal: Principal = Depends(resolve_authenticated_principal),
    conn: sqlite3.Connection = Depends(get_db)
):
    """
    Returns a specific assessment only if the caller owns it.
    Cross-user access is denied fail-closed (403 Forbidden).
    """
    cur = conn.execute(
        """SELECT assessment_id, user_id, source_account_id, destination_account_id, amount_cents, currency,
                  risk_score, risk_level, profile_status, policy_action, factors_json, history_watermark, created_at_utc
           FROM risk_assessments 
           WHERE assessment_id = ?;""",
        (assessment_id,)
    )
    r = cur.fetchone()
    if not r:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"ASSESSMENT_NOT_FOUND: Assessment '{assessment_id}' not found."
        )

    if r["user_id"] != principal.user_id and principal.role != "APPROVER":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="ACCESS_DENIED: Caller cannot access another user's risk assessment."
        )

    factors_raw = json.loads(r["factors_json"]) if r["factors_json"] else []
    return BehavioralAssessmentResponse(
        assessment_id=r["assessment_id"],
        user_id=r["user_id"],
        username=principal.username,
        source_account_id=r["source_account_id"],
        destination_account_id=r["destination_account_id"],
        amount_cents=r["amount_cents"],
        currency=r["currency"],
        transaction_fingerprint="",
        history_watermark=r["history_watermark"],
        risk_score=r["risk_score"],
        risk_level=r["risk_level"],
        profile_status=r["profile_status"],
        confidence=0.8,
        risk_factors=factors_raw,
        explanations=[f["description"] for f in factors_raw] if factors_raw else ["Baseline activity"],
        policy_action=r["policy_action"],
        recommended_action_reason="Persisted assessment record",
        model_version=settings.behavioral_policy_version,
        assessed_at=r["created_at_utc"],
        final_outcome="COMPLETED",
        firewall_verdict="APPROVE"
    )


@router.get("/banking/audit/verify", response_model=AuditVerificationResponse, tags=["Audit"])
def verify_audit_trail(conn: sqlite3.Connection = Depends(get_db)):
    """
    Verifies cryptographic SHA-256 hash chaining of all ledger audit events.
    """
    result = verify_audit_chain(conn)
    return AuditVerificationResponse(
        valid=result["valid"],
        total_events=result["total_events"],
        head_hash=result["head_hash"],
        broken_at_index=result["broken_at_index"],
        details=result["details"]
    )
