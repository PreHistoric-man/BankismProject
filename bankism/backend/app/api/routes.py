"""FastAPI router endpoints for health and firewall inspection."""

import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, status

from ..audit.logger import security_logger
from ..audit.recorder import AuditRecorder, get_audit_recorder
from ..banking.mock_data import MOCK_ACCOUNTS
from ..classification.detector import ThreatDetector
from ..config import Settings, get_settings
from ..policies.engine import PolicyEngine
from ..schemas.common import RiskLevel, ThreatCategory, Verdict
from ..schemas.firewall import (
    FirewallInspectRequest,
    FirewallInspectResponse,
    HealthResponse,
    PolicyViolation,
    ThreatDetail,
)
from ..security.masking import mask_sensitive_data
from ..security.sanitization import sanitize_input

router = APIRouter()


def get_threat_detector(settings: Settings = Depends(get_settings)) -> ThreatDetector:
    """Dependency provider for ThreatDetector."""
    return ThreatDetector(
        enable_heuristics=settings.enable_heuristic_detection,
        enable_metadata_checks=settings.enable_payment_metadata_checks,
    )


def get_policy_engine(settings: Settings = Depends(get_settings)) -> PolicyEngine:
    """Dependency provider for PolicyEngine."""
    return PolicyEngine(
        risk_block_threshold=settings.risk_block_threshold,
        risk_review_threshold=settings.risk_review_threshold,
        high_amount_threshold=settings.high_amount_threshold,
    )


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Health check and subsystem readiness",
    tags=["System"],
)
async def health_check(settings: Settings = Depends(get_settings)) -> HealthResponse:
    """Return health status of Bankism firewall and its security subsystems."""
    return HealthResponse(
        status="healthy",
        app_name=settings.app_name,
        version=settings.app_version,
        environment=settings.environment,
        timestamp=datetime.now(timezone.utc),
        subsystems={
            "firewall_inspector": "ready",
            "threat_detector": "ready",
            "policy_engine": "ready",
            "sanitizer": "ready",
            "masking_engine": "ready",
            "audit_recorder": "ready",
            "banking_guardrails": "enforced",
            "ledger_database": "ready",
            "audit_hash_chain": "ready",
            "deterministic_authorization": "ready",
        },
    )


@router.post(
    "/firewall/inspect",
    response_model=FirewallInspectResponse,
    summary="Inspect untrusted natural-language banking request",
    tags=["Firewall"],
)
async def inspect_request(
    request: FirewallInspectRequest,
    detector: ThreatDetector = Depends(get_threat_detector),
    policy_engine: PolicyEngine = Depends(get_policy_engine),
    recorder: AuditRecorder = Depends(get_audit_recorder),
    settings: Settings = Depends(get_settings),
) -> FirewallInspectResponse:
    """Intercept and inspect an untrusted banking prompt before execution.

    Applies:
    1. Input sanitization (Unicode NFKC, invisible bytes removal, length bounds)
    2. PCI-DSS & GLBA sensitive data masking
    3. Multi-vector threat detection (Prompt injection, jailbreak, SQLi/XSS metadata, obfuscation)
    4. Deterministic policy rules & risk scoring
    5. Phase 1 execution prevention guardrail (execution_permitted is strictly False)
    6. Masked audit trail logging
    """
    start_time = time.perf_counter()
    inspection_id = str(uuid.uuid4())

    try:
        raw_prompt = request.prompt

        # Step 1: Input sanitization
        sanitized_prompt = sanitize_input(raw_prompt)

        # Step 2: Sensitive data masking for safe logging & display
        masked_prompt = mask_sensitive_data(sanitized_prompt)

        # Step 3: Threat detection
        threats, risk_score, primary_threat = detector.detect_threats(
            raw_prompt=raw_prompt,
            sanitized_prompt=sanitized_prompt,
            operation=request.proposed_operation,
        )

        # Step 4: Policy Engine evaluation
        verdict, risk_level, violations, reasons, requires_step_up = policy_engine.evaluate_policies(
            threats=threats,
            risk_score=risk_score,
            operation=request.proposed_operation,
        )

        # Step 5: Enforce Phase 1 execution safety guardrail
        # CRITICAL INVARIANT: In Phase 1, execution_permitted is PERMANENTLY and UNCONDITIONALLY False.
        # It is never controlled by user input, configuration overrides, classifier output, or request metadata.
        execution_permitted: bool = False

        latency_ms = round((time.perf_counter() - start_time) * 1000, 2)

        response = FirewallInspectResponse(
            inspection_id=inspection_id,
            verdict=verdict,
            risk_level=risk_level,
            risk_score=risk_score,
            primary_threat=primary_threat,
            threats_detected=threats,
            policy_violations=violations,
            sanitized_prompt=sanitized_prompt,
            masked_prompt=masked_prompt,
            requires_step_up_auth=requires_step_up,
            execution_permitted=execution_permitted,
            reasons=reasons,
            timestamp=datetime.now(timezone.utc),
            evaluation_latency_ms=latency_ms,
        )

        # Step 6: Log audit event with masked data only
        security_logger.info(
            f"Inspection completed: id={inspection_id} verdict={verdict.value} "
            f"risk={risk_level.value} score={risk_score:.2f} latency={latency_ms}ms "
            f"prompt='{masked_prompt[:120]}'"
        )

        # Step 7: Record to audit store
        recorder.record_inspection(response, metadata=request.metadata)

        return response

    except Exception as exc:
        # FAIL-CLOSED PRINCIPLE:
        # Any unexpected error in the firewall MUST default to BLOCK with CRITICAL risk.
        latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
        security_logger.error(f"Firewall inspection error for id={inspection_id}: {str(exc)}")

        fail_closed_response = FirewallInspectResponse(
            inspection_id=inspection_id,
            verdict=Verdict.BLOCK,
            risk_level=RiskLevel.CRITICAL,
            risk_score=1.0,
            primary_threat=ThreatCategory.INVALID_INPUT,
            threats_detected=[
                ThreatDetail(
                    category=ThreatCategory.INVALID_INPUT,
                    confidence=1.0,
                    description="Internal firewall safety exception triggered; request blocked fail-closed.",
                    severity=RiskLevel.CRITICAL,
                )
            ],
            policy_violations=[
                PolicyViolation(
                    rule_id="FAIL-CLOSED-001",
                    rule_name="Fail-Closed Exception Gate",
                    description="Security pipeline encountered an evaluation fault; operation blocked.",
                    required_action="Quarantine request and alert engineering.",
                )
            ],
            sanitized_prompt="",
            masked_prompt="[CONTENT_REDACTED_DUE_TO_PROCESSING_ERROR]",
            requires_step_up_auth=True,
            execution_permitted=False,
            reasons=["Fail-closed security trigger: unexpected processing error resulted in mandatory block."],
            timestamp=datetime.now(timezone.utc),
            evaluation_latency_ms=latency_ms,
        )
        return fail_closed_response


@router.get(
    "/firewall/audit/recent",
    response_model=List[Dict[str, Any]],
    summary="Get recent audit log entries",
    tags=["Audit"],
)
async def get_recent_audit(
    limit: int = 50,
    recorder: AuditRecorder = Depends(get_audit_recorder),
) -> List[Dict[str, Any]]:
    """Retrieve recent masked inspection audit entries."""
    return recorder.get_recent(limit=min(limit, 100))


@router.get(
    "/firewall/audit/metrics",
    response_model=Dict[str, Any],
    summary="Get aggregate firewall inspection metrics",
    tags=["Audit"],
)
async def get_audit_metrics(
    recorder: AuditRecorder = Depends(get_audit_recorder),
) -> Dict[str, Any]:
    """Retrieve summary metrics of approved, blocked, and reviewed counts."""
    return recorder.get_summary_metrics()


@router.get(
    "/banking/simulated-accounts",
    summary="List simulated test accounts (Deprecated public mock view)",
    tags=["Banking Simulator"],
)
async def list_simulated_accounts() -> Dict[str, Any]:
    """Retrieve fictional test accounts for sandbox testing."""
    return {
        "status": "simulation_only",
        "accounts": [acc.model_dump() for acc in MOCK_ACCOUNTS.values()],
    }


# ===========================================================================
# Phase 2: Trusted Identity, Authorized Ledger & Transaction Sandboxing
# ===========================================================================

from ..audit.tamper_evident import get_tamper_evident_audit_store
from ..authorization.dual_approval import get_dual_approval_manager
from ..authorization.service import get_authorization_service
from ..authorization.tickets import AuthorizationTicket
from ..executor.executor import ExecutionReceipt, get_transaction_executor
from ..ledger.db import get_db_connection
from ..ledger.models import cents_to_dollars, dollars_to_cents
from ..ledger.operations import (
    get_account_by_id_db,
    get_account_transactions,
)
from ..schemas.auth import AuthenticatedPrincipal
from ..schemas.banking import (
    AccountBalanceResponse,
    ConfirmTransferRequest,
    DualApproveRequest,
    PrepareTransferRequest,
)
from ..security.auth import (
    authorize_account_ownership,
    get_authenticated_principal,
)
from ..profiling.engine import get_behavioral_risk_engine
from ..risk.evaluation import run_synthetic_calibration_suite
from ..risk.profile_service import get_profile_service
from ..schemas.profiling import (
    HistoricalStats,
    RiskAssessment,
    RiskAssessmentListResponse,
    UserProfileResponse,
)


@router.get(
    "/banking/accounts",
    summary="List accounts owned by authenticated principal",
    tags=["Banking Ledger"],
)
async def get_my_accounts(
    principal: AuthenticatedPrincipal = Depends(get_authenticated_principal),
) -> List[Dict[str, Any]]:
    """Retrieve all accounts owned by the verified caller.

    Cross-user accounts are strictly isolated.
    """
    with get_db_connection() as conn:
        cursor = conn.execute(
            """SELECT account_id, user_id, account_name, account_type,
                      balance_cents, currency, daily_limit_cents, is_active
               FROM accounts WHERE user_id = ?;""",
            (principal.user_id,),
        )
        accounts = []
        for row in cursor.fetchall():
            accounts.append({
                "account_id": row["account_id"],
                "user_id": row["user_id"],
                "account_name": row["account_name"],
                "account_type": row["account_type"],
                "balance_cents": row["balance_cents"],
                "balance_dollars": cents_to_dollars(row["balance_cents"]),
                "currency": row["currency"],
                "daily_limit_dollars": cents_to_dollars(row["daily_limit_cents"]),
                "is_active": bool(row["is_active"]),
            })
        return accounts


@router.get(
    "/banking/accounts/{account_id}/balance",
    response_model=AccountBalanceResponse,
    summary="Get verified balance of an authorized account",
    tags=["Banking Ledger"],
)
async def get_account_balance(
    account_id: str,
    principal: AuthenticatedPrincipal = Depends(get_authenticated_principal),
) -> AccountBalanceResponse:
    """Retrieve balance of account after verifying ownership."""
    authorize_account_ownership(principal, account_id)

    with get_db_connection() as conn:
        acc = get_account_by_id_db(conn, account_id)
        if not acc:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Account '{account_id}' was not found in ledger.",
            )
        return AccountBalanceResponse(
            account_id=acc.account_id,
            user_id=acc.user_id,
            account_name=acc.account_name,
            account_type=acc.account_type,
            balance_cents=acc.balance_cents,
            balance_dollars=acc.balance_dollars,
            currency=acc.currency,
            daily_limit_dollars=acc.daily_limit_dollars,
        )


@router.get(
    "/banking/accounts/{account_id}/transactions",
    summary="Get verified transaction history of an authorized account",
    tags=["Banking Ledger"],
)
async def get_account_history(
    account_id: str,
    limit: int = 50,
    principal: AuthenticatedPrincipal = Depends(get_authenticated_principal),
) -> List[Dict[str, Any]]:
    """Retrieve transaction history after verifying ownership."""
    authorize_account_ownership(principal, account_id)
    safe_limit = max(1, min(limit, 100))

    with get_db_connection() as conn:
        records = get_account_transactions(conn, account_id, limit=safe_limit)
        return [r.model_dump() for r in records]


@router.post(
    "/banking/transfers/prepare",
    summary="Prepare and authorize a simulated transfer",
    tags=["Banking Transfers"],
)
async def prepare_transfer(
    req: PrepareTransferRequest,
    principal: AuthenticatedPrincipal = Depends(get_authenticated_principal),
    settings: Settings = Depends(get_settings),
) -> Dict[str, Any]:
    """Validate transfer, evaluate firewall & policy rules, and issue signed authorization ticket.

    If high-risk threshold is met, creates a pending dual-approval request.
    """
    try:
        amount_cents = dollars_to_cents(req.amount)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid monetary amount: {exc}",
        )

    auth_service = get_authorization_service()

    with get_db_connection() as conn:
        try:
            result = auth_service.prepare_transfer_authorization(
                conn=conn,
                principal=principal,
                source_account_id=req.source_account_id,
                destination_account_id=req.destination_account_id,
                amount_cents=amount_cents,
                currency=req.currency,
                memo=req.memo,
                prompt=req.prompt,
                context=req.context,
            )
            return result
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"error": "AUTHORIZATION_FAILED", "message": str(exc)},
            )


@router.post(
    "/banking/transfers/confirm",
    response_model=ExecutionReceipt,
    summary="Execute an authorized transfer via the single protected execution gateway",
    tags=["Banking Transfers"],
)
async def confirm_transfer(
    req: ConfirmTransferRequest,
    principal: AuthenticatedPrincipal = Depends(get_authenticated_principal),
) -> ExecutionReceipt:
    """Consume authorization ticket atomically and execute simulated ledger transfer."""
    executor = get_transaction_executor()

    with get_db_connection() as conn:
        try:
            receipt = executor.execute_transfer(
                conn=conn,
                principal=principal,
                ticket=req.ticket,
                idempotency_key=req.idempotency_key,
            )
            return receipt
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"error": "EXECUTION_REJECTED", "message": str(exc)},
            )


@router.post(
    "/banking/transfers/approve",
    response_model=AuthorizationTicket,
    summary="Submit secondary approval for a high-risk transfer",
    tags=["Banking Transfers"],
)
async def approve_transfer(
    req: DualApproveRequest,
    principal: AuthenticatedPrincipal = Depends(get_authenticated_principal),
    settings: Settings = Depends(get_settings),
) -> AuthorizationTicket:
    """Secondary approver signs off on high-risk transaction."""
    dual_approvals = get_dual_approval_manager()

    with get_db_connection() as conn:
        try:
            ticket = dual_approvals.approve_transaction(
                conn=conn,
                request_id=req.request_id,
                approver=principal,
                secret_key=settings.hmac_secret,
            )
            return ticket
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"error": "DUAL_APPROVAL_REJECTED", "message": str(exc)},
            )


@router.get(
    "/banking/audit/verify",
    summary="Verify cryptographic integrity of the persistent audit hash chain",
    tags=["Audit"],
)
async def verify_audit_chain() -> Dict[str, Any]:
    """Verify unbroken SHA-256 hash chain of the SQLite audit events."""
    audit_store = get_tamper_evident_audit_store()
    with get_db_connection() as conn:
        is_valid, count, error = audit_store.verify_chain_integrity(conn)
        return {
            "is_valid": is_valid,
            "verified_records_count": count,
            "error": error,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }


# ===========================================================================
# Phase 3: User Threat Profiling & Behavioral Risk Intelligence Endpoints
# ===========================================================================

@router.get(
    "/banking/profiling/me",
    response_model=UserProfileResponse,
    summary="Get behavioral threat profile and historical anomaly standing for authenticated user",
    tags=["Behavioral Profiling"],
)
async def get_my_behavioral_profile(
    account_id: Optional[str] = None,
    principal: AuthenticatedPrincipal = Depends(get_authenticated_principal),
) -> UserProfileResponse:
    """Retrieve explainable, deterministic threat standing and history analysis."""
    profile_service = get_profile_service()
    with get_db_connection() as conn:
        return profile_service.get_authenticated_profile(
            conn=conn,
            principal=principal,
            account_id=account_id,
        )


@router.get(
    "/banking/risk/profile",
    response_model=UserProfileResponse,
    summary="Get behavioral risk profile for authenticated principal (Phase 3.5)",
    tags=["Behavioral Profiling"],
)
async def get_risk_profile(
    account_id: Optional[str] = None,
    principal: AuthenticatedPrincipal = Depends(get_authenticated_principal),
) -> UserProfileResponse:
    """Retrieve behavioral risk profile scoped strictly to the authenticated principal and owned account."""
    profile_service = get_profile_service()
    with get_db_connection() as conn:
        return profile_service.get_authenticated_profile(
            conn=conn,
            principal=principal,
            account_id=account_id,
        )


@router.get(
    "/banking/profiling/stats",
    response_model=HistoricalStats,
    summary="Get 30-day rolling historical transaction statistics for authenticated user",
    tags=["Behavioral Profiling"],
)
async def get_my_historical_stats(
    account_id: Optional[str] = None,
    days_window: int = 30,
    principal: AuthenticatedPrincipal = Depends(get_authenticated_principal),
) -> HistoricalStats:
    """Retrieve rolling statistics (mean, median, variance, counterparty list) for an account or user."""
    safe_window = max(1, min(days_window, 365))
    profile_service = get_profile_service()
    with get_db_connection() as conn:
        return profile_service.get_authenticated_stats(
            conn=conn,
            principal=principal,
            account_id=account_id,
            days_window=safe_window,
        )


@router.get(
    "/banking/risk/assessments",
    response_model=RiskAssessmentListResponse,
    summary="List persisted behavioral risk assessments for authenticated principal",
    tags=["Behavioral Profiling"],
)
async def list_risk_assessments(
    account_id: Optional[str] = None,
    limit: int = 20,
    offset: int = 0,
    principal: AuthenticatedPrincipal = Depends(get_authenticated_principal),
) -> RiskAssessmentListResponse:
    """Retrieve bounded, paginated behavioral risk assessments for the authenticated user."""
    if limit < 1 or limit > 100:
        limit = max(1, min(limit, 100))
    if offset < 0:
        offset = 0

    profile_service = get_profile_service()
    with get_db_connection() as conn:
        items, total = profile_service.list_authenticated_assessments(
            conn=conn,
            principal=principal,
            account_id=account_id,
            limit=limit,
            offset=offset,
        )
        return RiskAssessmentListResponse(
            user_id=principal.user_id,
            total=total,
            limit=limit,
            offset=offset,
            assessments=items,
        )


@router.get(
    "/banking/risk/assessments/{assessment_id}",
    response_model=RiskAssessment,
    summary="Get a specific persisted behavioral risk assessment by ID",
    tags=["Behavioral Profiling"],
)
async def get_risk_assessment_detail(
    assessment_id: str,
    principal: AuthenticatedPrincipal = Depends(get_authenticated_principal),
) -> RiskAssessment:
    """Retrieve a single behavioral risk assessment, enforcing strict principal ownership."""
    profile_service = get_profile_service()
    with get_db_connection() as conn:
        return profile_service.get_authenticated_assessment_by_id(
            conn=conn,
            principal=principal,
            assessment_id=assessment_id,
        )


@router.get(
    "/banking/risk/evaluation",
    summary="Run reproducible synthetic scenario calibration benchmark (Phase 3.8)",
    tags=["Behavioral Profiling"],
)
async def get_synthetic_risk_evaluation(
    seed: int = 42,
    principal: AuthenticatedPrincipal = Depends(get_authenticated_principal),
) -> Dict[str, Any]:
    """Return reproducible synthetic evaluation results across 8 behavioral scenario families."""
    return run_synthetic_calibration_suite(seed=seed)
