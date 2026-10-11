"""
Response Models for Bankism API
"""
from typing import List, Optional, Dict, Any
from pydantic import BaseModel
from .common import Verdict, RiskLevel, ThreatCategory, ProfileStatus, BehavioralPolicyAction, UserRole


class ThreatDetail(BaseModel):
    category: ThreatCategory
    confidence: float
    description: str
    matched_pattern: Optional[str] = None
    severity: RiskLevel


class PolicyViolation(BaseModel):
    rule_id: str
    rule_name: str
    description: str
    required_action: str


class InspectResponse(BaseModel):
    inspection_id: str
    verdict: Verdict
    risk_level: RiskLevel
    risk_score: float
    primary_threat: ThreatCategory
    threats_detected: List[ThreatDetail]
    policy_violations: List[PolicyViolation]
    sanitized_prompt: str
    masked_prompt: str
    requires_step_up_auth: bool
    execution_permitted: bool = False
    reasons: List[str]
    evaluation_latency_ms: float
    timestamp: str


class BehavioralRiskFactor(BaseModel):
    name: str
    category: str
    score: float
    observed_fact: str
    inference: str
    description: str


class BehavioralAssessmentResponse(BaseModel):
    assessment_id: str
    user_id: str
    username: str
    source_account_id: str
    destination_account_id: str
    amount_cents: int
    currency: str = "USD"
    transaction_fingerprint: str
    history_watermark: str
    risk_score: float
    risk_level: RiskLevel
    profile_status: ProfileStatus
    confidence: float
    risk_factors: List[BehavioralRiskFactor]
    explanations: List[str]
    policy_action: BehavioralPolicyAction
    recommended_action_reason: str
    model_version: str
    assessed_at: str
    final_outcome: str
    firewall_verdict: Verdict


class DualApprovalRequestInfo(BaseModel):
    request_id: str
    initiator_user_id: str
    source_account_id: str
    destination_account_id: str
    amount_dollars: float
    reason: str
    status: str
    expires_at_utc: str


class TransferPrepareResponse(BaseModel):
    status: str
    ticket: Optional[Dict[str, Any]] = None
    dual_approval_request: Optional[DualApprovalRequestInfo] = None
    risk_assessment: BehavioralAssessmentResponse
    reasons: List[str]


class ExecutionReceipt(BaseModel):
    tx_id: str
    source_account_id: str
    destination_account_id: str
    amount_dollars: float
    amount_cents: int
    currency: str = "USD"
    audit_event_hash: str
    executed_at_utc: str


class TransferConfirmResponse(BaseModel):
    status: str
    receipt: ExecutionReceipt


class AccountInfo(BaseModel):
    account_id: str
    name: str
    owner: str
    balance_dollars: float
    balance_cents: int
    daily_limit_dollars: float


class UserProfileResponse(BaseModel):
    user_id: str
    username: str
    role: UserRole
    profile_status: ProfileStatus
    transaction_count: int
    count_1h: int
    count_24h: int
    failed_24h: int
    mean_dollars: float
    median_dollars: float
    std_dollars: float
    max_dollars: float
    known_counterparties: List[str]
    history_watermark: str


class AuditVerificationResponse(BaseModel):
    valid: bool
    total_events: int
    head_hash: Optional[str] = None
    broken_at_index: Optional[int] = None
    details: str
