"""Deterministic baseline feature extraction for user behavioral profiles."""

import sqlite3
from typing import Optional
from ..profiling.engine import get_behavioral_risk_engine
from ..schemas.profiling import FEATURE_LIMITATIONS_DOC, HistoricalStats


def extract_user_baseline_features(
    conn: sqlite3.Connection,
    user_id: str,
    account_id: Optional[str] = None,
    days_window: int = 30,
) -> HistoricalStats:
    """Extract trusted historical transaction features for a verified principal and owned account."""
    engine = get_behavioral_risk_engine()
    return engine.get_historical_stats(
        conn=conn,
        user_id=user_id,
        account_id=account_id,
        days_window=days_window,
    )


__all__ = ["extract_user_baseline_features", "FEATURE_LIMITATIONS_DOC"]
