"""Deterministic Authorization Service for Bankism simulated transactions."""

import sqlite3
import uuid
from typing import Any, Dict, Optional
from ..classification.detector import ThreatDetector
from ..config import get_settings
from ..ledger.models import SUPPORTED_CURRENCIES
from ..ledger.operations import get_account_by_id_db
from ..policies.engine import PolicyEngine
from ..profiling.engine import BehavioralRiskEngine, get_behavioral_risk_engine
from ..schemas.auth import AuthenticatedPrincipal
from ..schemas.common import Verdict
from ..schemas.firewall import ProposedOperation
from ..schemas.profiling import (
    BehavioralRiskLevel,
    PolicyRecommendation,
    RecommendedAction,
    RiskAssessment,
)
from ..security.auth import authorize_account_ownership
from .dual_approval import DualApprovalManager, get_dual_approval_manager
from .tickets import (
    AuthorizationTicket,
    CanonicalTransaction,
    compute_canonical_fingerprint,
    create_authorization_ticket,
)


class AuthorizationService:
    """Trusted authorization service independent of the AI classifier.

    An AI verdict of APPROVE is NEVER sufficient alone to authorize execution.
    Deterministic rules, account ownership, funds verification, limits, and
    behavioral risk intelligence are mandatory.
    """

    def __init__(
        self,
        detector: ThreatDetector,
        policy_engine: PolicyEngine,
        dual_approvals: DualApprovalManager,
        risk_engine: Optional[BehavioralRiskEngine] = None,
    ):
        self.detector = detector
        self.policy_engine = policy_engine
        self.dual_approvals = dual_approvals
        self.risk_engine = risk_engine or get_behavioral_risk_engine()

    def prepare_transfer_authorization(
        self,
        conn: sqlite3.Connection,
        principal: AuthenticatedPrincipal,
        source_account_id: str,
        destination_account_id: str,
        amount_cents: int,
        currency: str = "USD",
        memo: Optional[str] = None,
        prompt: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Verify all deterministic controls and issue ticket or dual-approval request."""
        # 1. Enforce account ownership access boundary
        authorize_account_ownership(principal, source_account_id)

        # 2. Validate transfer parameters
        if amount_cents <= 0:
            raise ValueError("Transfer amount must be positive.")

        if source_account_id == destination_account_id:
            raise ValueError("Source and destination accounts must be distinct.")

        currency_upper = currency.upper()
        if currency_upper not in SUPPORTED_CURRENCIES:
            raise ValueError(f"Currency '{currency}' is not supported.")

        # 3. Validate accounts existence, active status, and matching currency in DB
        src_account = get_account_by_id_db(conn, source_account_id)
        if not src_account or not src_account.is_active:
            raise ValueError(f"Source account '{source_account_id}' is invalid or inactive.")
        if src_account.currency != currency_upper:
            raise ValueError(
                f"Source account currency '{src_account.currency}' does not match requested currency '{currency_upper}'."
            )

        dst_account = get_account_by_id_db(conn, destination_account_id)
        if not dst_account or not dst_account.is_active:
            raise ValueError(f"Destination account '{destination_account_id}' is invalid or inactive.")
        if dst_account.currency != currency_upper:
            raise ValueError(
                f"Destination account currency '{dst_account.currency}' does not match requested currency '{currency_upper}'."
            )

        # 4. Check sufficient balance in ledger
        if src_account.balance_cents < amount_cents:
            self.risk_engine.record_transfer_attempt(
                conn=conn,
                user_id=principal.user_id,
                source_account_id=source_account_id,
                destination_account_id=destination_account_id,
                amount_cents=amount_cents,
                outcome="REJECTED_VALIDATION",
                currency=currency_upper,
                reason="Insufficient funds",
            )
            raise ValueError(
                f"Insufficient funds: Available balance is {src_account.balance_cents} cents "
                f"(${src_account.balance_dollars:.2f}), requested {amount_cents} cents."
            )

        # 5. Check daily transfer limit
        cur = conn.execute(
            """SELECT COALESCE(SUM(amount_cents), 0) AS daily_sum
               FROM simulated_transactions
               WHERE source_account_id = ?
                 AND created_at >= datetime('now', '-1 day')
                 AND status = 'COMPLETED';""",
            (source_account_id,),
        )
        row = cur.fetchone()
        daily_spent = row["daily_sum"] if row else 0

        if daily_spent + amount_cents > src_account.daily_limit_cents:
            self.risk_engine.record_transfer_attempt(
                conn=conn,
                user_id=principal.user_id,
                source_account_id=source_account_id,
                destination_account_id=destination_account_id,
                amount_cents=amount_cents,
                outcome="REJECTED_VALIDATION",
                currency=currency_upper,
                reason="Daily transfer limit exceeded",
            )
            raise ValueError(
                f"Daily transfer limit exceeded: spent {daily_spent} cents, "
                f"limit {src_account.daily_limit_cents} cents."
            )

        canonical_tx = CanonicalTransaction(
            transaction_nonce=f"nonce_{uuid.uuid4().hex[:12]}",
            initiator_user_id=principal.user_id,
            source_account_id=source_account_id,
            destination_account_id=destination_account_id,
            amount_cents=amount_cents,
            currency=currency_upper,
            memo=memo,
        )
        tx_fingerprint = compute_canonical_fingerprint(canonical_tx)

        # 6. Run AI Security Firewall on prompt if provided
        op = ProposedOperation(
            action="TRANSFER_FUNDS",
            source_account_id=source_account_id,
            destination_account_id=destination_account_id,
            amount=amount_cents / 100.0,
            currency=currency_upper,
            memo=memo,
        )

        effective_prompt = prompt or f"Transfer ${amount_cents / 100:.2f} from {source_account_id} to {destination_account_id}"
        threats, risk_score, _ = self.detector.detect_threats(
            raw_prompt=effective_prompt,
            sanitized_prompt=effective_prompt,
            operation=op,
        )
        verdict, risk_level, violations, reasons, step_up = self.policy_engine.evaluate_policies(
            threats=threats,
            risk_score=risk_score,
            operation=op,
        )

        # INVARIANT: Low behavioral risk or clean history NEVER overrides a firewall BLOCK
        if verdict == Verdict.BLOCK:
            violation_details = "; ".join(v.description for v in violations) or "; ".join(reasons)
            self.risk_engine.record_transfer_attempt(
                conn=conn,
                user_id=principal.user_id,
                source_account_id=source_account_id,
                destination_account_id=destination_account_id,
                amount_cents=amount_cents,
                outcome="BLOCKED_FIREWALL",
                currency=currency_upper,
                reason=violation_details,
            )
            raise ValueError(f"Transfer blocked by AI Security Firewall: {violation_details}")

        # 7. Behavioral Risk Assessment (User Threat Profiling) with fail-safe exception handling
        try:
            behavioral_assessment: RiskAssessment = self.risk_engine.assess_transaction_risk(
                conn=conn,
                user_id=principal.user_id,
                source_account_id=source_account_id,
                destination_account_id=destination_account_id,
                amount_cents=amount_cents,
                context=context,
                transaction_fingerprint=tx_fingerprint,
                currency=currency_upper,
                persist=False,
            )
        except Exception as exc:
            behavioral_assessment = self.risk_engine._build_fail_safe_assessment(
                user_id=principal.user_id,
                source_account_id=source_account_id,
                destination_account_id=destination_account_id,
                amount_cents=amount_cents,
                reason=f"Behavioral risk engine unavailable or failed: {exc}",
            )
            behavioral_assessment.transaction_fingerprint = tx_fingerprint

        settings = get_settings()

        # Escalation logic:
        # Dual approval required if:
        # a) High-risk amount threshold reached
        # b) Firewall gave REVIEW verdict or step_up required
        # c) Behavioral assessment recommends DUAL_APPROVAL, BLOCK, REQUIRE_DUAL_APPROVAL, or HOLD_FOR_TRUSTED_REVIEW
        # d) Behavioral risk level is HIGH (when configured) or CRITICAL
        requires_dual = (
            self.dual_approvals.requires_dual_approval(amount_cents)
            or verdict == Verdict.REVIEW
            or step_up
            or behavioral_assessment.recommended_action in (RecommendedAction.DUAL_APPROVAL, RecommendedAction.BLOCK)
            or behavioral_assessment.policy_action in (
                PolicyRecommendation.REQUIRE_DUAL_APPROVAL,
                PolicyRecommendation.HOLD_FOR_TRUSTED_REVIEW,
            )
            or behavioral_assessment.risk_level == BehavioralRiskLevel.CRITICAL
            or (
                getattr(settings, "high_behavioral_risk_requires_dual_approval", True)
                and behavioral_assessment.risk_level == BehavioralRiskLevel.HIGH
            )
        )

        # Step-up required if behavioral risk tier is ELEVATED/HIGH_RISK or recommended STEP_UP_AUTH
        requires_step_up = (
            step_up
            or behavioral_assessment.recommended_action in (
                RecommendedAction.STEP_UP_AUTH,
                RecommendedAction.SUPERVISORY_REVIEW,
            )
            or behavioral_assessment.policy_action == PolicyRecommendation.STEP_UP_REVIEW
            or behavioral_assessment.risk_level in (
                BehavioralRiskLevel.MEDIUM,
                BehavioralRiskLevel.HIGH,
                BehavioralRiskLevel.CRITICAL,
            )
        )

        if requires_dual:
            approval_record = self.dual_approvals.create_approval_request(conn, canonical_tx)
            behavioral_assessment.final_outcome = "PENDING_DUAL_APPROVAL"
            self.risk_engine.persist_assessment(conn, behavioral_assessment, record_audit=True)
            self.risk_engine.record_transfer_attempt(
                conn=conn,
                user_id=principal.user_id,
                source_account_id=source_account_id,
                destination_account_id=destination_account_id,
                amount_cents=amount_cents,
                outcome="DUAL_APPROVAL_REQUIRED",
                currency=currency_upper,
                reason=behavioral_assessment.recommended_action_reason,
                assessment_id=behavioral_assessment.assessment_id,
            )
            return {
                "status": "PENDING_DUAL_APPROVAL",
                "message": (
                    f"Transaction requires secondary approval. Created approval request '{approval_record['request_id']}'. "
                    f"A second authorized approver must approve before execution."
                ),
                "approval_request": approval_record,
                "behavioral_assessment": behavioral_assessment.model_dump(),
            }

        # 8. Standard single authorization: Issue signed AuthorizationTicket
        ticket = create_authorization_ticket(
            tx=canonical_tx,
            secret_key=settings.hmac_secret,
            lifetime_seconds=settings.ticket_expiry_seconds,
        )
        behavioral_assessment.final_outcome = "AUTHORIZED"
        self.risk_engine.persist_assessment(conn, behavioral_assessment, record_audit=True)
        self.risk_engine.record_transfer_attempt(
            conn=conn,
            user_id=principal.user_id,
            source_account_id=source_account_id,
            destination_account_id=destination_account_id,
            amount_cents=amount_cents,
            outcome="PREPARED",
            currency=currency_upper,
            reason="Authorized under deterministic & behavioral policy",
            assessment_id=behavioral_assessment.assessment_id,
        )

        return {
            "status": "AUTHORIZED",
            "message": "Transaction authorized. Authorization ticket issued for execution.",
            "ticket": ticket,
            "requires_step_up_auth": requires_step_up,
            "behavioral_assessment": behavioral_assessment.model_dump(),
        }


def get_authorization_service() -> AuthorizationService:
    settings = get_settings()
    detector = ThreatDetector(
        enable_heuristics=settings.enable_heuristic_detection,
        enable_metadata_checks=settings.enable_payment_metadata_checks,
    )
    policy_engine = PolicyEngine(
        risk_block_threshold=settings.risk_block_threshold,
        risk_review_threshold=settings.risk_review_threshold,
        high_amount_threshold=settings.high_amount_threshold,
    )
    dual_approvals = get_dual_approval_manager()
    risk_engine = get_behavioral_risk_engine()
    return AuthorizationService(detector, policy_engine, dual_approvals, risk_engine)
