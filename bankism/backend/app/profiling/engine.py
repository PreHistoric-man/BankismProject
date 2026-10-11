"""Deterministic Behavioral Risk Intelligence & User Threat Profiling Engine.

CRITICAL ARCHITECTURAL CONSTRAINTS & GOLDEN RULES:
1. The behavioral risk engine NEVER directly executes a transfer.
2. A low risk score must NEVER override a BLOCK or REVIEW firewall decision.
3. Behavioral analysis must NOT grant account ownership, identity, privileges, or approval authority.
4. A low behavioral risk score must NOT bypass transaction limits, balance checks, or security controls.
5. High behavioral risk ESCALATES required controls (e.g. elevating ALLOW to STEP_UP_AUTH or DUAL_APPROVAL).
6. Cold-start accounts (insufficient history) default to SAFE, proportionate handling with standard baseline limits.
7. Explanations must be deterministic, human-auditable, and privacy-preserving.
"""

import math
import sqlite3
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from ..schemas.profiling import (
    HistoricalStats,
    RecommendedAction,
    RiskAssessment,
    RiskFactor,
    ThreatTier,
    UserProfileResponse,
)


class BehavioralRiskEngine:
    """Deterministic, explainable behavioral anomaly and threat profiling engine."""

    # Baseline configuration thresholds
    AMOUNT_SPIKE_Z_SCORE_THRESHOLD = 2.5
    AMOUNT_SPIKE_RATIO_THRESHOLD = 3.0
    VELOCITY_HOURLY_BURST_THRESHOLD = 3
    VELOCITY_DAILY_BURST_THRESHOLD = 8
    OFF_HOURS_UTC_START = 1   # 01:00 UTC
    OFF_HOURS_UTC_END = 5     # 05:00 UTC

    def __init__(self, conn: Optional[sqlite3.Connection] = None):
        self.conn = conn

    def get_historical_stats(
        self,
        conn: sqlite3.Connection,
        user_id: str,
        account_id: Optional[str] = None,
        days_window: int = 30,
    ) -> HistoricalStats:
        """Compute rolling historical statistics for a user/account from the simulated ledger.

        Uses the completed transactions in the ledger.
        """
        query = """
            SELECT st.amount_cents, st.destination_account_id, st.created_at
            FROM simulated_transactions st
            JOIN accounts a ON st.source_account_id = a.account_id
            WHERE a.user_id = ?
              AND st.status = 'COMPLETED'
              AND st.created_at >= datetime('now', ?)
        """
        params: List[Any] = [user_id, f"-{days_window} days"]

        if account_id:
            query += " AND st.source_account_id = ?"
            params.append(account_id)

        cursor = conn.execute(query, params)
        rows = cursor.fetchall()

        if not rows:
            return HistoricalStats(
                user_id=user_id,
                account_id=account_id,
                transaction_count=0,
                mean_amount_cents=0.0,
                std_amount_cents=0.0,
                max_amount_cents=0,
                min_amount_cents=0,
                window_days=days_window,
                known_counterparties=[],
                avg_daily_velocity=0.0,
            )

        amounts = [r["amount_cents"] for r in rows]
        counterparties = list(set(r["destination_account_id"] for r in rows))
        count = len(amounts)
        mean = sum(amounts) / count

        if count > 1:
            variance = sum((x - mean) ** 2 for x in amounts) / (count - 1)
            std = math.sqrt(variance)
        else:
            std = 0.0

        daily_velocity = count / max(1, days_window)

        return HistoricalStats(
            user_id=user_id,
            account_id=account_id,
            transaction_count=count,
            mean_amount_cents=round(mean, 2),
            std_amount_cents=round(std, 2),
            max_amount_cents=max(amounts),
            min_amount_cents=min(amounts),
            window_days=days_window,
            known_counterparties=counterparties,
            avg_daily_velocity=round(daily_velocity, 2),
        )

    def assess_transaction_risk(
        self,
        conn: sqlite3.Connection,
        user_id: str,
        source_account_id: str,
        destination_account_id: str,
        amount_cents: int,
        context: Optional[Dict[str, Any]] = None,
    ) -> RiskAssessment:
        """Evaluate behavioral risk signals for a proposed transaction against user history.

        Deterministic signals:
        1. Amount Anomaly: Z-score > 2.5 or amount > 3x historical mean.
        2. Velocity Burst: Count of outgoing transfers within past 1 hour and past 24 hours.
        3. Counterparty Novelty: Destination account has never been transacted with.
        4. Time-of-Day Anomaly: Transaction scheduled during off-hours (01:00 - 05:00 UTC).
        5. Cold-Start Handling: Less than 3 historical transactions -> conservative baseline.
        """
        context = context or {}
        factors: List[RiskFactor] = []
        stats = self.get_historical_stats(conn, user_id=user_id, account_id=source_account_id, days_window=30)

        is_cold_start = stats.transaction_count < 3
        confidence = min(1.0, stats.transaction_count / 10.0) if not is_cold_start else 0.35

        # 1. Amount Anomaly Analysis
        if not is_cold_start and stats.mean_amount_cents > 0:
            ratio = amount_cents / stats.mean_amount_cents
            z_score = 0.0
            if stats.std_amount_cents > 0:
                z_score = (amount_cents - stats.mean_amount_cents) / stats.std_amount_cents

            if z_score >= self.AMOUNT_SPIKE_Z_SCORE_THRESHOLD or ratio >= self.AMOUNT_SPIKE_RATIO_THRESHOLD:
                anomaly_score = min(90.0, 40.0 + (ratio * 10.0) + (max(0.0, z_score) * 8.0))
                factors.append(
                    RiskFactor(
                        name="AMOUNT_SPIKE_ANOMALY",
                        score=round(anomaly_score, 1),
                        description=(
                            f"Proposed amount (${amount_cents / 100:.2f}) is significantly higher than historical average "
                            f"(${stats.mean_amount_cents / 100:.2f}) [ratio: {ratio:.1f}x, z-score: {z_score:.2f}]."
                        ),
                        metadata={"ratio": round(ratio, 2), "z_score": round(z_score, 2), "amount_cents": amount_cents},
                    )
                )
        elif is_cold_start:
            # Baseline benchmark for new accounts
            if amount_cents > 500000:  # > $5,000 for cold start
                factors.append(
                    RiskFactor(
                        name="COLD_START_HIGH_VALUE",
                        score=55.0,
                        description=(
                            f"High initial transaction value (${amount_cents / 100:.2f}) on account with limited baseline history "
                            f"({stats.transaction_count} prior transfers)."
                        ),
                        metadata={"transaction_count": stats.transaction_count, "amount_cents": amount_cents},
                    )
                )

        # 2. Velocity Burst Analysis (Recent transactions in last 1 hour and 24 hours)
        cur_1h = conn.execute(
            """SELECT COUNT(*) as cnt, COALESCE(SUM(amount_cents), 0) as total_1h
               FROM simulated_transactions
               WHERE source_account_id = ?
                 AND created_at >= datetime('now', '-1 hour')
                 AND status = 'COMPLETED';""",
            (source_account_id,),
        )
        row_1h = cur_1h.fetchone()
        count_1h = row_1h["cnt"] if row_1h else 0

        cur_24h = conn.execute(
            """SELECT COUNT(*) as cnt, COALESCE(SUM(amount_cents), 0) as total_24h
               FROM simulated_transactions
               WHERE source_account_id = ?
                 AND created_at >= datetime('now', '-24 hours')
                 AND status = 'COMPLETED';""",
            (source_account_id,),
        )
        row_24h = cur_24h.fetchone()
        count_24h = row_24h["cnt"] if row_24h else 0

        if count_1h >= self.VELOCITY_HOURLY_BURST_THRESHOLD:
            burst_score = min(85.0, 45.0 + (count_1h * 10.0))
            factors.append(
                RiskFactor(
                    name="RAPID_VELOCITY_BURST_1H",
                    score=round(burst_score, 1),
                    description=f"Rapid succession of {count_1h} outgoing transfers within the last hour.",
                    metadata={"count_1h": count_1h, "count_24h": count_24h},
                )
            )
        elif count_24h >= self.VELOCITY_DAILY_BURST_THRESHOLD:
            factors.append(
                RiskFactor(
                    name="ELEVATED_DAILY_VELOCITY",
                    score=40.0,
                    description=f"Unusually high volume of {count_24h} outgoing transfers in the last 24 hours.",
                    metadata={"count_24h": count_24h},
                )
            )

        # 3. Novel Counterparty Analysis
        if destination_account_id not in stats.known_counterparties:
            if not is_cold_start:
                novelty_score = 35.0
                factors.append(
                    RiskFactor(
                        name="NOVEL_COUNTERPARTY",
                        score=novelty_score,
                        description=(
                            f"Recipient account '{destination_account_id}' has not been transacted with previously "
                            f"(out of {len(stats.known_counterparties)} known beneficiaries)."
                        ),
                        metadata={
                            "destination_account_id": destination_account_id,
                            "known_beneficiaries_count": len(stats.known_counterparties),
                        },
                    )
                )
            else:
                # Cold-start accounts naturally transact with initial recipients; keep score minimal (5.0)
                factors.append(
                    RiskFactor(
                        name="INITIAL_COUNTERPARTY",
                        score=5.0,
                        description=f"Establishing transfer relationship with recipient '{destination_account_id}'.",
                        metadata={"destination_account_id": destination_account_id},
                    )
                )

        # 4. Off-Hours / Unusual Timing Analysis (default 02:00 - 05:00 UTC, unless simulated)
        # For cold-start routine transfers, we do not penalize standard daytime or late-evening activity
        now_utc = datetime.now(timezone.utc)
        current_hour = now_utc.hour
        eval_hour = context.get("simulated_hour_utc", current_hour)
        if context.get("simulated_hour_utc") is not None or (self.OFF_HOURS_UTC_START <= eval_hour < self.OFF_HOURS_UTC_END):
            if self.OFF_HOURS_UTC_START <= eval_hour < self.OFF_HOURS_UTC_END:
                factors.append(
                    RiskFactor(
                        name="OFF_HOURS_ACTIVITY",
                        score=25.0,
                        description=f"Activity originated during unusual off-hours window ({eval_hour:02d}:00 UTC).",
                        metadata={"hour_utc": eval_hour},
                    )
                )

        # 5. Composite Risk Score Calculation
        if not factors:
            composite_score = 5.0  # Clean baseline
        else:
            # Weighted diminishing returns calculation
            # Highest factor contributes 60%, others contribute proportionally
            sorted_scores = sorted([f.score for f in factors], reverse=True)
            primary = sorted_scores[0]
            secondary_sum = sum(sorted_scores[1:])
            composite_score = min(98.0, primary + (secondary_sum * 0.25))

        composite_score = round(composite_score, 1)

        # Determine Threat Tier
        if composite_score >= 75.0:
            threat_tier = ThreatTier.CRITICAL_RISK
        elif composite_score >= 50.0:
            threat_tier = ThreatTier.HIGH_RISK
        elif composite_score >= 25.0:
            threat_tier = ThreatTier.ELEVATED
        else:
            threat_tier = ThreatTier.STANDARD

        # Determine Proportionate Recommended Action
        # (Escalates controls, never weakens firewall)
        if threat_tier == ThreatTier.CRITICAL_RISK:
            recommended_action = RecommendedAction.DUAL_APPROVAL
            recommended_reason = "Critical behavioral anomalies detected; secondary supervisory approval recommended."
        elif threat_tier == ThreatTier.HIGH_RISK:
            recommended_action = RecommendedAction.STEP_UP_AUTH
            recommended_reason = "High behavioral risk signals present; step-up verification recommended."
        elif threat_tier == ThreatTier.ELEVATED:
            recommended_action = RecommendedAction.SUPERVISORY_REVIEW
            recommended_reason = "Elevated risk signals detected; additional confirmation recommended."
        else:
            recommended_action = RecommendedAction.ALLOW
            recommended_reason = "Behavior conforms to expected profile within normal tolerance."

        top_explanations = [f.description for f in sorted(factors, key=lambda x: x.score, reverse=True)[:3]]

        return RiskAssessment(
            user_id=user_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            risk_score=composite_score,
            threat_tier=threat_tier,
            confidence=round(confidence, 2),
            factors=factors,
            top_explanations=top_explanations,
            recommended_action=recommended_action,
            recommended_action_reason=recommended_reason,
            history_events_analyzed=stats.transaction_count,
            is_cold_start=is_cold_start,
        )

    def get_user_profile(self, conn: sqlite3.Connection, user_id: str, username: str) -> UserProfileResponse:
        """Retrieve aggregated behavioral threat profile for a user."""
        stats = self.get_historical_stats(conn, user_id=user_id, days_window=30)

        # Determine standing profile risk
        # Check past 24h burst or active flags
        cur_recent = conn.execute(
            """SELECT COUNT(*) as recent_cnt, COALESCE(SUM(amount_cents), 0) as recent_sum
               FROM simulated_transactions st
               JOIN accounts a ON st.source_account_id = a.account_id
               WHERE a.user_id = ?
                 AND st.created_at >= datetime('now', '-24 hours')
                 AND st.status = 'COMPLETED';""",
            (user_id,),
        )
        rec = cur_recent.fetchone()
        recent_count = rec["recent_cnt"] if rec else 0

        active_factors: List[RiskFactor] = []
        base_score = 10.0

        if recent_count >= self.VELOCITY_DAILY_BURST_THRESHOLD:
            active_factors.append(
                RiskFactor(
                    name="ACTIVE_HIGH_VELOCITY",
                    score=40.0,
                    description=f"{recent_count} transactions initiated in the past 24 hours.",
                )
            )
            base_score += 35.0

        if stats.transaction_count == 0:
            active_factors.append(
                RiskFactor(
                    name="NEW_ACCOUNT_PROFILE",
                    score=15.0,
                    description="No completed transaction history established yet (cold start).",
                )
            )
            base_score += 10.0

        if base_score >= 75.0:
            tier = ThreatTier.CRITICAL_RISK
        elif base_score >= 50.0:
            tier = ThreatTier.HIGH_RISK
        elif base_score >= 25.0:
            tier = ThreatTier.ELEVATED
        else:
            tier = ThreatTier.STANDARD

        return UserProfileResponse(
            user_id=user_id,
            username=username,
            threat_tier=tier,
            current_risk_score=min(100.0, base_score),
            total_transactions_analyzed=stats.transaction_count,
            known_counterparties_count=len(stats.known_counterparties),
            last_assessed_at=datetime.now(timezone.utc).isoformat(),
            active_risk_factors=active_factors,
            historical_stats=stats,
        )


_risk_engine_instance: Optional[BehavioralRiskEngine] = None


def get_behavioral_risk_engine() -> BehavioralRiskEngine:
    global _risk_engine_instance
    if _risk_engine_instance is None:
        _risk_engine_instance = BehavioralRiskEngine()
    return _risk_engine_instance
