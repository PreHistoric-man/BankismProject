"""Versioned behavioral scoring policy and threshold mapping."""

from typing import Dict
from ..config import Settings, get_settings
from ..schemas.profiling import (
    BehavioralRiskLevel,
    PolicyRecommendation,
    RecommendedAction,
    ThreatTier,
)

SCORING_POLICY_DOCUMENTATION: Dict[str, str] = {
    "version": "phase3-v1.0.0",
    "bounds": "0.0 to 100.0 (capped at 98.0 for statistical factors, 85.0 for fail-safe data errors)",
    "deduplication": (
        "Risk factors are grouped into orthogonal signal categories (AMOUNT, VELOCITY, COUNTERPARTY, "
        "ATTEMPT_PATTERN, TIMING, INTEGRITY). Within each category, only the highest-scoring factor is "
        "counted so correlated indicators (e.g. z-score and mean-ratio, or 1h and 24h velocity) are never double-counted."
    ),
    "aggregation": (
        "Primary category factor contributes 100% of its weighted score; secondary independent categories "
        "contribute 25% of their weighted score. If 3 or more independent categories trigger with score >= 20, "
        "a +10.0 multi-signal convergence adjustment is added."
    ),
    "thresholds": (
        "LOW (0.0-24.9) -> ALLOW_UNDER_EXISTING_POLICY; "
        "MEDIUM (25.0-49.9) -> STEP_UP_REVIEW; "
        "HIGH (50.0-74.9) -> REQUIRE_DUAL_APPROVAL; "
        "CRITICAL (75.0-100.0) -> HOLD_FOR_TRUSTED_REVIEW (requires secondary approver)."
    ),
}


def map_score_to_policy(
    score: float,
    is_cold_start: bool = False,
    settings: Settings | None = None,
) -> tuple[BehavioralRiskLevel, ThreatTier, RecommendedAction, PolicyRecommendation]:
    """Deterministically map a bounded 0-100 risk score to severity tier and policy action."""
    cfg = settings or get_settings()
    if score >= cfg.behavioral_risk_critical_threshold:
        return (
            BehavioralRiskLevel.CRITICAL,
            ThreatTier.CRITICAL_RISK,
            RecommendedAction.DUAL_APPROVAL,
            PolicyRecommendation.HOLD_FOR_TRUSTED_REVIEW,
        )
    if score >= cfg.behavioral_risk_high_threshold:
        return (
            BehavioralRiskLevel.HIGH,
            ThreatTier.HIGH_RISK,
            RecommendedAction.STEP_UP_AUTH,
            PolicyRecommendation.REQUIRE_DUAL_APPROVAL,
        )
    if score >= cfg.behavioral_risk_medium_threshold:
        return (
            BehavioralRiskLevel.MEDIUM,
            ThreatTier.ELEVATED,
            RecommendedAction.SUPERVISORY_REVIEW,
            PolicyRecommendation.STEP_UP_REVIEW,
        )
    return (
        BehavioralRiskLevel.LOW,
        ThreatTier.STANDARD,
        RecommendedAction.ALLOW,
        PolicyRecommendation.ALLOW_UNDER_EXISTING_POLICY,
    )
