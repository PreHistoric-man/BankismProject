"""FastAPI router endpoints for health and firewall inspection."""

import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List
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
        # Crucial security rule: LLM classifications or inspection verdicts NEVER authorize real transactions.
        # Phase 1 explicitly sets execution_permitted = False
        execution_permitted = False
        if settings.allow_transaction_execution:
            # Explicitly overridable only when simulated execution is unlocked in future phases
            execution_permitted = (verdict == Verdict.APPROVE) and not requires_step_up

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
    summary="List simulated test accounts",
    tags=["Banking Simulator"],
)
async def list_simulated_accounts() -> Dict[str, Any]:
    """Retrieve fictional test accounts for sandbox testing."""
    return {
        "status": "simulation_only",
        "accounts": [acc.model_dump() for acc in MOCK_ACCOUNTS.values()],
    }
