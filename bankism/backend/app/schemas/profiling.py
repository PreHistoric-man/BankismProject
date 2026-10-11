"""Phase 3 User Threat Profiling and Behavioral Risk Intelligence Schemas."""

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, model_validator


class ThreatTier(str, Enum):
    """User threat tier based on cumulative and current risk signals."""
    STANDARD = "STANDARD"          # 0 - 24.9
    ELEVATED = "ELEVATED"          # 25 - 49.9
    HIGH_RISK = "HIGH_RISK"        # 50 - 74.9
    CRITICAL_RISK = "CRITICAL_RISK"# 75 - 100


class BehavioralRiskLevel(str, Enum):
    """Standardized behavioral risk severity levels."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ProfileStatus(str, Enum):
    """Explicit behavioral baseline maturity status."""
    ESTABLISHED = "ESTABLISHED"
    INSUFFICIENT_HISTORY = "INSUFFICIENT_HISTORY"


class PolicyRecommendation(str, Enum):
    """Explicit versioned policy action recommendations for Phase 3.2/3.3."""
    ALLOW_UNDER_EXISTING_POLICY = "ALLOW_UNDER_EXISTING_POLICY"
    STEP_UP_REVIEW = "STEP_UP_REVIEW"
    REQUIRE_DUAL_APPROVAL = "REQUIRE_DUAL_APPROVAL"
    HOLD_FOR_TRUSTED_REVIEW = "HOLD_FOR_TRUSTED_REVIEW"


class RecommendedAction(str, Enum):
    """Proportionate recommended action from behavioral risk assessment.

    Includes aliases for both Phase 3.2 policy action names and existing code conventions.
    """
    ALLOW = "ALLOW"
    ALLOW_UNDER_EXISTING_POLICY = "ALLOW"
    STEP_UP_AUTH = "STEP_UP_AUTH"
    STEP_UP_REVIEW = "STEP_UP_AUTH"
    SUPERVISORY_REVIEW = "SUPERVISORY_REVIEW"
    DUAL_APPROVAL = "DUAL_APPROVAL"
    REQUIRE_DUAL_APPROVAL = "DUAL_APPROVAL"
    BLOCK = "BLOCK"
    HOLD_FOR_TRUSTED_REVIEW = "BLOCK"


FEATURE_LIMITATIONS_DOC: Dict[str, str] = {
    "amount_deviation": (
        "A large transfer relative to past average/median indicates an unusual amount for this account, "
        "which may reflect a legitimate one-off purchase, invoice, or tax payment rather than fraud."
    ),
    "recipient_novelty": (
        "Transacting with a new or infrequently used recipient is normal when onboarding vendors or paying new contacts; "
        "it warrants contextual review only when combined with other signals or high values."
    ),
    "velocity_change": (
        "Short-term bursts in transfer frequency can occur during legitimate batch payroll or bill-pay sessions."
    ),
    "failed_or_blocked_attempts": (
        "Recent rejected or blocked attempts may result from user typos or balance misunderstandings, "
        "though repeated rapid failures can indicate probing or credential misuse."
    ),
    "cold_start_baseline": (
        "Accounts with fewer than the minimum required historical transactions are marked INSUFFICIENT_HISTORY; "
        "missing history is never treated as proof of low risk nor as grounds for automatic blocking."
    ),
}


class RiskFactor(BaseModel):
    """Specific behavioral risk factor with score, category, observed fact, inference, and explanation."""
    name: str = Field(..., description="Machine-readable factor code (e.g. AMOUNT_SPIKE_ANOMALY)")
    category: str = Field(default="GENERAL", description="Signal family to prevent correlated double-counting")
    score: float = Field(..., ge=0.0, le=100.0, description="Bounded risk contribution of this factor (0-100)")
    weight: float = Field(default=1.0, ge=0.0, le=2.0, description="Policy weight applied to this signal family")
    observed_fact: str = Field(default="", description="Verifiable factual measurement from trusted ledger history")
    inference: str = Field(default="", description="Analytical interpretation of why the fact is unusual")
    description: str = Field(..., description="Concise human-readable explanation of why this factor was triggered")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Traceable input values used to compute factor")


class HistoricalStats(BaseModel):
    """Statistical summary and baseline features extracted from trusted ledger history."""
    user_id: str
    account_id: Optional[str] = None
    currency: str = "USD"
    profile_status: ProfileStatus = ProfileStatus.INSUFFICIENT_HISTORY
    transaction_count: int = 0
    count_1h: int = 0
    count_24h: int = 0
    count_7d: int = 0
    mean_amount_cents: float = 0.0
    median_amount_cents: float = 0.0
    std_amount_cents: float = 0.0
    iqr_amount_cents: float = 0.0
    max_amount_cents: int = 0
    min_amount_cents: int = 0
    window_days: int = 30
    known_counterparties: List[str] = Field(default_factory=list)
    counterparty_counts: Dict[str, int] = Field(default_factory=dict)
    avg_daily_velocity: float = 0.0
    velocity_change_ratio: float = 0.0
    seconds_since_last_tx: Optional[float] = None
    recent_failed_or_blocked_count_24h: int = 0
    repeated_attempt_count_1h: int = 0
    history_watermark: str = ""
    feature_limitations: Dict[str, str] = Field(default_factory=lambda: dict(FEATURE_LIMITATIONS_DOC))


class RiskAssessment(BaseModel):
    """Comprehensive, deterministic behavioral risk intelligence assessment."""
    assessment_id: str = Field(default_factory=lambda: f"ras_{uuid.uuid4().hex[:14]}")
    user_id: str
    source_account_id: Optional[str] = None
    destination_account_id: Optional[str] = None
    amount_cents: int = 0
    currency: str = "USD"
    transaction_fingerprint: Optional[str] = None
    history_watermark: str = ""
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    assessed_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    model_version: str = "phase3-v1.0.0"
    risk_score: float = Field(..., ge=0.0, le=100.0, description="Overall bounded behavioral risk score (0-100)")
    risk_level: BehavioralRiskLevel = BehavioralRiskLevel.LOW
    threat_tier: ThreatTier = ThreatTier.STANDARD
    profile_status: ProfileStatus = ProfileStatus.INSUFFICIENT_HISTORY
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence in baseline maturity (0-1)")
    factors: List[RiskFactor] = Field(default_factory=list)
    risk_factors: List[RiskFactor] = Field(default_factory=list)
    top_explanations: List[str] = Field(default_factory=list)
    explanations: List[str] = Field(default_factory=list)
    recommended_action: RecommendedAction = RecommendedAction.ALLOW
    policy_action: PolicyRecommendation = PolicyRecommendation.ALLOW_UNDER_EXISTING_POLICY
    recommended_action_reason: str = ""
    history_events_analyzed: int = 0
    is_cold_start: bool = False
    final_outcome: str = "ASSESSED"
    audit_event_hash: Optional[str] = None
    feature_summary: Dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def sync_compatible_fields(self) -> "RiskAssessment":
        """Ensure dual field names stay synchronized for API consumers and tests."""
        if self.factors and not self.risk_factors:
            self.risk_factors = list(self.factors)
        elif self.risk_factors and not self.factors:
            self.factors = list(self.risk_factors)

        if self.top_explanations and not self.explanations:
            self.explanations = list(self.top_explanations)
        elif self.explanations and not self.top_explanations:
            self.top_explanations = list(self.explanations)

        if self.timestamp and not self.assessed_at:
            self.assessed_at = self.timestamp
        return self


class UserProfileResponse(BaseModel):
    """Public safe profile view of an authenticated user's behavioral threat standing."""
    user_id: str
    username: str
    profile_status: ProfileStatus = ProfileStatus.INSUFFICIENT_HISTORY
    risk_level: BehavioralRiskLevel = BehavioralRiskLevel.LOW
    threat_tier: ThreatTier
    current_risk_score: float = Field(..., ge=0.0, le=100.0)
    model_version: str = "phase3-v1.0.0"
    total_transactions_analyzed: int
    known_counterparties_count: int
    recent_failed_attempts_24h: int = 0
    last_assessed_at: str
    active_risk_factors: List[RiskFactor] = Field(default_factory=list)
    explanations: List[str] = Field(default_factory=list)
    historical_stats: HistoricalStats
    recent_assessments: List[RiskAssessment] = Field(default_factory=list)
    feature_limitations: Dict[str, str] = Field(default_factory=lambda: dict(FEATURE_LIMITATIONS_DOC))


class RiskAssessmentListResponse(BaseModel):
    """Paginated response of persisted behavioral risk assessments for an authenticated user."""
    user_id: str
    total: int
    limit: int
    offset: int
    assessments: List[RiskAssessment] = Field(default_factory=list)

