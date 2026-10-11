"""Phase 3 User Threat Profiling and Behavioral Risk Intelligence Schemas."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ThreatTier(str, Enum):
    """User threat tier based on cumulative and current risk signals."""
    STANDARD = "STANDARD"          # 0 - 24
    ELEVATED = "ELEVATED"          # 25 - 49
    HIGH_RISK = "HIGH_RISK"        # 50 - 74
    CRITICAL_RISK = "CRITICAL_RISK"# 75 - 100


class RecommendedAction(str, Enum):
    """Proportionate recommended action from behavioral risk assessment."""
    ALLOW = "ALLOW"
    STEP_UP_AUTH = "STEP_UP_AUTH"
    SUPERVISORY_REVIEW = "SUPERVISORY_REVIEW"
    DUAL_APPROVAL = "DUAL_APPROVAL"
    BLOCK = "BLOCK"


class RiskFactor(BaseModel):
    """Specific behavioral risk factor with score and human-readable explanation."""
    name: str = Field(..., description="Short factor code or name")
    score: float = Field(..., ge=0.0, le=100.0, description="Risk contribution of this factor (0-100)")
    description: str = Field(..., description="Explainable description of why this factor was flagged")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Contextual details (e.g. z-score, velocity)")


class RiskAssessment(BaseModel):
    """Comprehensive behavioral risk intelligence assessment for a user or transaction."""
    user_id: str
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    risk_score: float = Field(..., ge=0.0, le=100.0, description="Overall behavioral risk score (0-100)")
    threat_tier: ThreatTier
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence in assessment based on history volume")
    factors: List[RiskFactor] = Field(default_factory=list)
    top_explanations: List[str] = Field(default_factory=list)
    recommended_action: RecommendedAction
    recommended_action_reason: str
    history_events_analyzed: int = 0
    is_cold_start: bool = False


class HistoricalStats(BaseModel):
    """Statistical summary of historical activity for an account/user."""
    user_id: str
    account_id: Optional[str] = None
    transaction_count: int
    mean_amount_cents: float
    std_amount_cents: float
    max_amount_cents: int
    min_amount_cents: int
    window_days: int = 30
    known_counterparties: List[str] = Field(default_factory=list)
    avg_daily_velocity: float = 0.0


class UserProfileResponse(BaseModel):
    """Public safe profile view of a user's threat standing."""
    user_id: str
    username: str
    threat_tier: ThreatTier
    current_risk_score: float
    total_transactions_analyzed: int
    known_counterparties_count: int
    last_assessed_at: str
    active_risk_factors: List[RiskFactor] = Field(default_factory=list)
    historical_stats: HistoricalStats
