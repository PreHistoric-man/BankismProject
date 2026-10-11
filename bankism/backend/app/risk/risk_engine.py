"""Risk engine service facade for Phase 3 behavioral risk intelligence."""

from ..profiling.engine import BehavioralRiskEngine, get_behavioral_risk_engine

__all__ = ["BehavioralRiskEngine", "get_behavioral_risk_engine"]
