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

import hashlib
import json
import math
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from ..audit.tamper_evident import get_tamper_evident_audit_store
from ..config import Settings, get_settings
from ..schemas.profiling import (
    FEATURE_LIMITATIONS_DOC,
    BehavioralRiskLevel,
    HistoricalStats,
    PolicyRecommendation,
    ProfileStatus,
    RecommendedAction,
    RiskAssessment,
    RiskFactor,
    ThreatTier,
    UserProfileResponse,
)


class BehavioralRiskEngine:
    """Deterministic, explainable behavioral anomaly and threat profiling engine."""

    # Default baseline configuration thresholds (overridable via Settings)
    AMOUNT_SPIKE_Z_SCORE_THRESHOLD = 2.5
    AMOUNT_SPIKE_RATIO_THRESHOLD = 3.0
    VELOCITY_HOURLY_BURST_THRESHOLD = 3
    VELOCITY_DAILY_BURST_THRESHOLD = 8
    REPEATED_FAILED_ATTEMPTS_THRESHOLD = 3
    OFF_HOURS_UTC_START = 1   # 01:00 UTC
    OFF_HOURS_UTC_END = 5     # 05:00 UTC

    def __init__(
        self,
        conn: Optional[sqlite3.Connection] = None,
        settings: Optional[Settings] = None,
    ):
        self.conn = conn
        self._settings = settings

    @property
    def settings(self) -> Settings:
        return self._settings or get_settings()

    @property
    def model_version(self) -> str:
        return getattr(self.settings, "behavioral_policy_version", "phase3-v1.0.0")

    @property
    def min_history_transactions(self) -> int:
        return max(1, int(getattr(self.settings, "min_history_transactions", 3)))

    @staticmethod
    def _compute_median_and_iqr(sorted_values: List[int]) -> Tuple[float, float]:
        """Compute exact deterministic median and interquartile range (IQR) from sorted integers."""
        n = len(sorted_values)
        if n == 0:
            return 0.0, 0.0
        if n == 1:
            return float(sorted_values[0]), 0.0

        def _percentile(vals: List[int], p: float) -> float:
            k = (len(vals) - 1) * p
            f = math.floor(k)
            c = math.ceil(k)
            if f == c:
                return float(vals[int(k)])
            return vals[f] * (c - k) + vals[c] * (k - f)

        median = _percentile(sorted_values, 0.5)
        q1 = _percentile(sorted_values, 0.25)
        q3 = _percentile(sorted_values, 0.75)
        return round(median, 2), round(max(0.0, q3 - q1), 2)

    @staticmethod
    def _table_exists(conn: sqlite3.Connection, table_name: str) -> bool:
        cur = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?;",
            (table_name,),
        )
        return cur.fetchone() is not None

    def record_transfer_attempt(
        self,
        conn: sqlite3.Connection,
        user_id: str,
        source_account_id: str,
        destination_account_id: str,
        amount_cents: int,
        outcome: str,
        currency: str = "USD",
        reason: Optional[str] = None,
        assessment_id: Optional[str] = None,
    ) -> Optional[str]:
        """Record a server-validated transfer attempt (including rejected/blocked attempts)."""
        if not self._table_exists(conn, "transfer_attempts"):
            return None
        attempt_id = f"att_{uuid.uuid4().hex[:14]}"
        conn.execute(
            """INSERT INTO transfer_attempts
               (attempt_id, user_id, source_account_id, destination_account_id,
                amount_cents, currency, outcome, reason, assessment_id)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);""",
            (
                attempt_id,
                user_id,
                source_account_id,
                destination_account_id,
                max(0, int(amount_cents)),
                currency,
                outcome,
                (reason or "")[:500],
                assessment_id,
            ),
        )
        return attempt_id

    def get_historical_stats(
        self,
        conn: sqlite3.Connection,
        user_id: str,
        account_id: Optional[str] = None,
        days_window: Optional[int] = None,
    ) -> HistoricalStats:
        """Compute rolling historical statistics and baseline features for an authenticated user/account.

        Strictly scopes queries to accounts owned by `user_id`.
        """
        if not user_id or not isinstance(user_id, str):
            raise ValueError("Valid authenticated user_id is required for historical stats.")

        effective_window = days_window if days_window is not None else getattr(self.settings, "behavioral_window_days", 30)
        effective_window = max(1, min(int(effective_window), 365))

        # Verify account ownership if account_id is specified and exists in accounts table
        currency = "USD"
        if account_id:
            acc_row = conn.execute(
                "SELECT user_id, currency FROM accounts WHERE account_id = ?;",
                (account_id,),
            ).fetchone()
            if acc_row and acc_row["user_id"] != user_id:
                raise PermissionError(
                    f"Profile isolation violation: Account '{account_id}' does not belong to user '{user_id}'."
                )
            if acc_row and acc_row["currency"]:
                currency = acc_row["currency"]

        query = """
            SELECT st.transaction_id, st.amount_cents, st.destination_account_id, st.created_at
            FROM simulated_transactions st
            JOIN accounts a ON st.source_account_id = a.account_id
            WHERE a.user_id = ?
              AND st.status = 'COMPLETED'
              AND st.created_at >= datetime('now', ?)
        """
        params: List[Any] = [user_id, f"-{effective_window} days"]

        if account_id:
            query += " AND st.source_account_id = ?"
            params.append(account_id)

        query += " ORDER BY st.created_at DESC, st.rowid DESC"

        cursor = conn.execute(query, params)
        rows = cursor.fetchall()

        # Windowed velocity counts (1h, 24h, 7d) scoped to user_id (and account_id if provided)
        def _count_window(window_expr: str) -> int:
            w_sql = """
                SELECT COUNT(*) as cnt
                FROM simulated_transactions st
                JOIN accounts a ON st.source_account_id = a.account_id
                WHERE a.user_id = ?
                  AND st.status = 'COMPLETED'
                  AND st.created_at >= datetime('now', ?)
            """
            w_params: List[Any] = [user_id, window_expr]
            if account_id:
                w_sql += " AND st.source_account_id = ?"
                w_params.append(account_id)
            r = conn.execute(w_sql, w_params).fetchone()
            return int(r["cnt"]) if r else 0

        count_1h = _count_window("-1 hour")
        count_24h = _count_window("-24 hours")
        count_7d = _count_window("-7 days")

        # Failed / blocked / rejected attempts in last 24h
        failed_24h = 0
        repeated_1h = 0
        if self._table_exists(conn, "transfer_attempts"):
            f_sql = """
                SELECT COUNT(*) as cnt
                FROM transfer_attempts
                WHERE user_id = ?
                  AND outcome IN ('BLOCKED_FIREWALL', 'REJECTED_VALIDATION', 'FAILED_EXECUTION')
                  AND created_at >= datetime('now', '-24 hours')
            """
            f_params: List[Any] = [user_id]
            if account_id:
                f_sql += " AND source_account_id = ?"
                f_params.append(account_id)
            f_row = conn.execute(f_sql, f_params).fetchone()
            failed_24h = int(f_row["cnt"]) if f_row else 0

            rep_sql = """
                SELECT COALESCE(MAX(pair_cnt), 0) as max_rep
                FROM (
                    SELECT COUNT(*) as pair_cnt
                    FROM transfer_attempts
                    WHERE user_id = ?
                      AND created_at >= datetime('now', '-1 hour')
                    GROUP BY source_account_id, destination_account_id, amount_cents
                );
            """
            rep_row = conn.execute(rep_sql, (user_id,)).fetchone()
            repeated_1h = int(rep_row["max_rep"]) if rep_row else 0

        # Time since last transaction
        seconds_since_last: Optional[float] = None
        latest_tx_id = "NONE"
        if rows:
            latest_tx_id = str(rows[0]["transaction_id"])
            try:
                sec_row = conn.execute(
                    "SELECT (strftime('%s', 'now') - strftime('%s', ?)) AS diff_sec;",
                    (rows[0]["created_at"],),
                ).fetchone()
                if sec_row and sec_row["diff_sec"] is not None:
                    seconds_since_last = max(0.0, float(sec_row["diff_sec"]))
            except Exception:
                seconds_since_last = None

        count = len(rows)
        profile_status = (
            ProfileStatus.ESTABLISHED
            if count >= self.min_history_transactions
            else ProfileStatus.INSUFFICIENT_HISTORY
        )

        watermark_raw = (
            f"{user_id}|{account_id or 'ALL'}|{count}|{latest_tx_id}|"
            f"{count_1h}|{count_24h}|{failed_24h}"
        )
        history_watermark = hashlib.sha256(watermark_raw.encode("utf-8")).hexdigest()[:24]

        if not rows:
            return HistoricalStats(
                user_id=user_id,
                account_id=account_id,
                currency=currency,
                profile_status=profile_status,
                transaction_count=0,
                count_1h=count_1h,
                count_24h=count_24h,
                count_7d=count_7d,
                mean_amount_cents=0.0,
                median_amount_cents=0.0,
                std_amount_cents=0.0,
                iqr_amount_cents=0.0,
                max_amount_cents=0,
                min_amount_cents=0,
                window_days=effective_window,
                known_counterparties=[],
                counterparty_counts={},
                avg_daily_velocity=0.0,
                velocity_change_ratio=0.0,
                seconds_since_last_tx=None,
                recent_failed_or_blocked_count_24h=failed_24h,
                repeated_attempt_count_1h=repeated_1h,
                history_watermark=history_watermark,
                feature_limitations=dict(FEATURE_LIMITATIONS_DOC),
            )

        amounts = [int(r["amount_cents"]) for r in rows]
        sorted_amounts = sorted(amounts)
        counterparty_counts: Dict[str, int] = {}
        for r in rows:
            dst = str(r["destination_account_id"])
            counterparty_counts[dst] = counterparty_counts.get(dst, 0) + 1
        counterparties = sorted(counterparty_counts.keys())

        mean = sum(amounts) / count
        if count > 1:
            variance = sum((x - mean) ** 2 for x in amounts) / (count - 1)
            std = math.sqrt(variance)
        else:
            std = 0.0

        median, iqr = self._compute_median_and_iqr(sorted_amounts)
        daily_velocity = count / max(1, effective_window)
        velocity_change_ratio = round(count_24h / max(0.25, daily_velocity), 2) if count_24h > 0 else 0.0

        return HistoricalStats(
            user_id=user_id,
            account_id=account_id,
            currency=currency,
            profile_status=profile_status,
            transaction_count=count,
            count_1h=count_1h,
            count_24h=count_24h,
            count_7d=count_7d,
            mean_amount_cents=round(mean, 2),
            median_amount_cents=median,
            std_amount_cents=round(std, 2),
            iqr_amount_cents=iqr,
            max_amount_cents=max(amounts),
            min_amount_cents=min(amounts),
            window_days=effective_window,
            known_counterparties=counterparties,
            counterparty_counts=counterparty_counts,
            avg_daily_velocity=round(daily_velocity, 2),
            velocity_change_ratio=velocity_change_ratio,
            seconds_since_last_tx=seconds_since_last,
            recent_failed_or_blocked_count_24h=failed_24h,
            repeated_attempt_count_1h=repeated_1h,
            history_watermark=history_watermark,
            feature_limitations=dict(FEATURE_LIMITATIONS_DOC),
        )

    def _build_fail_safe_assessment(
        self,
        user_id: str,
        source_account_id: Optional[str],
        destination_account_id: Optional[str],
        amount_cents: Any,
        reason: str,
    ) -> RiskAssessment:
        """Fail-safe assessment when input or state is missing, malformed, or inconsistent.

        Golden Rule 6 & Requirement 3.2.9: Missing or malformed data NEVER silently produces a low-risk assessment.
        """
        safe_amount = amount_cents if isinstance(amount_cents, int) and not isinstance(amount_cents, bool) and amount_cents > 0 else 0
        factor = RiskFactor(
            name="FAIL_SAFE_DATA_INCONSISTENCY",
            category="INTEGRITY",
            score=85.0,
            weight=1.0,
            observed_fact=f"Risk evaluation received malformed or inconsistent input: {reason}",
            inference="Assessment cannot verify normal behavioral baseline; escalating to mandatory review fail-safely.",
            description=f"Fail-safe escalation triggered: {reason}",
            metadata={"reason": reason},
        )
        now_iso = datetime.now(timezone.utc).isoformat()
        return RiskAssessment(
            user_id=str(user_id or "UNKNOWN"),
            source_account_id=source_account_id,
            destination_account_id=destination_account_id,
            amount_cents=safe_amount,
            timestamp=now_iso,
            assessed_at=now_iso,
            model_version=self.model_version,
            risk_score=85.0,
            risk_level=BehavioralRiskLevel.CRITICAL,
            threat_tier=ThreatTier.CRITICAL_RISK,
            profile_status=ProfileStatus.INSUFFICIENT_HISTORY,
            confidence=0.0,
            factors=[factor],
            risk_factors=[factor],
            top_explanations=[factor.description],
            explanations=[factor.description],
            recommended_action=RecommendedAction.DUAL_APPROVAL,
            policy_action=PolicyRecommendation.HOLD_FOR_TRUSTED_REVIEW,
            recommended_action_reason="Fail-safe hold: behavioral assessment encountered missing or inconsistent input data.",
            history_events_analyzed=0,
            is_cold_start=True,
            final_outcome="FAIL_SAFE_ESCALATED",
        )

    def assess_transaction_risk(
        self,
        conn: sqlite3.Connection,
        user_id: str,
        source_account_id: str,
        destination_account_id: str,
        amount_cents: int,
        context: Optional[Dict[str, Any]] = None,
        transaction_fingerprint: Optional[str] = None,
        currency: str = "USD",
        persist: bool = True,
    ) -> RiskAssessment:
        """Evaluate behavioral risk signals for a proposed transaction against trusted user history.

        Deterministic signals (deduplicated by category to prevent correlated double-counting):
        1. AMOUNT: Z-score >= threshold or ratio >= threshold vs historical baseline (or cold-start high value).
        2. VELOCITY: 1-hour burst or 24-hour elevated volume / abrupt frequency shift.
        3. COUNTERPARTY: Novel recipient or infrequent recipient.
        4. ATTEMPT_PATTERN: Recent failed/blocked attempts or repeated identical attempts.
        5. TIMING: Off-hours UTC window.
        """
        # Validate inputs for fail-safe handling
        if (
            conn is None
            or not user_id
            or not isinstance(user_id, str)
            or not source_account_id
            or not isinstance(source_account_id, str)
            or not destination_account_id
            or not isinstance(destination_account_id, str)
            or not isinstance(amount_cents, int)
            or isinstance(amount_cents, bool)
            or amount_cents <= 0
        ):
            return self._build_fail_safe_assessment(
                user_id=user_id,
                source_account_id=source_account_id,
                destination_account_id=destination_account_id,
                amount_cents=amount_cents,
                reason="Missing or non-positive transaction parameters supplied to risk engine.",
            )

        if source_account_id == destination_account_id:
            return self._build_fail_safe_assessment(
                user_id=user_id,
                source_account_id=source_account_id,
                destination_account_id=destination_account_id,
                amount_cents=amount_cents,
                reason="Source and destination accounts cannot be identical.",
            )

        try:
            stats = self.get_historical_stats(
                conn,
                user_id=user_id,
                account_id=source_account_id,
                days_window=getattr(self.settings, "behavioral_window_days", 30),
            )
        except PermissionError:
            # Re-raise ownership isolation violations explicitly
            raise
        except Exception as exc:
            return self._build_fail_safe_assessment(
                user_id=user_id,
                source_account_id=source_account_id,
                destination_account_id=destination_account_id,
                amount_cents=amount_cents,
                reason=f"Database error reading historical baseline: {exc}",
            )

        context = context or {}
        raw_factors: List[RiskFactor] = []

        is_cold_start = stats.profile_status == ProfileStatus.INSUFFICIENT_HISTORY
        confidence = min(1.0, stats.transaction_count / 10.0) if not is_cold_start else 0.35

        z_thresh = float(getattr(self.settings, "amount_spike_z_score_threshold", self.AMOUNT_SPIKE_Z_SCORE_THRESHOLD))
        ratio_thresh = float(getattr(self.settings, "amount_spike_ratio_threshold", self.AMOUNT_SPIKE_RATIO_THRESHOLD))
        vel_1h_thresh = int(getattr(self.settings, "velocity_hourly_burst_threshold", self.VELOCITY_HOURLY_BURST_THRESHOLD))
        vel_24h_thresh = int(getattr(self.settings, "velocity_daily_burst_threshold", self.VELOCITY_DAILY_BURST_THRESHOLD))
        failed_thresh = int(getattr(self.settings, "repeated_failed_attempts_threshold", self.REPEATED_FAILED_ATTEMPTS_THRESHOLD))

        # ---------------------------------------------------------------------
        # 1. AMOUNT Category Analysis (single unified signal to avoid double-counting mean/median/z-score)
        # ---------------------------------------------------------------------
        if not is_cold_start and stats.mean_amount_cents > 0:
            ratio = amount_cents / stats.mean_amount_cents
            median_ref = stats.median_amount_cents if stats.median_amount_cents > 0 else stats.mean_amount_cents
            median_ratio = amount_cents / median_ref
            z_score = 0.0
            if stats.std_amount_cents > 0:
                z_score = (amount_cents - stats.mean_amount_cents) / stats.std_amount_cents

            if z_score >= z_thresh or ratio >= ratio_thresh:
                anomaly_score = min(90.0, 40.0 + (ratio * 10.0) + (max(0.0, z_score) * 8.0))
                raw_factors.append(
                    RiskFactor(
                        name="AMOUNT_SPIKE_ANOMALY",
                        category="AMOUNT",
                        score=round(anomaly_score, 1),
                        weight=1.0,
                        observed_fact=(
                            f"Amount ${amount_cents / 100:.2f} is {ratio:.1f}x the 30d mean (${stats.mean_amount_cents / 100:.2f}) "
                            f"and {median_ratio:.1f}x the median (${median_ref / 100:.2f})."
                        ),
                        inference="Transfer amount deviates substantially above this account's historical baseline.",
                        description=(
                            f"Proposed amount (${amount_cents / 100:.2f}) is significantly higher than historical average "
                            f"(${stats.mean_amount_cents / 100:.2f}) [ratio: {ratio:.1f}x, z-score: {z_score:.2f}]."
                        ),
                        metadata={
                            "ratio": round(ratio, 2),
                            "median_ratio": round(median_ratio, 2),
                            "z_score": round(z_score, 2),
                            "amount_cents": amount_cents,
                            "mean_amount_cents": stats.mean_amount_cents,
                            "median_amount_cents": stats.median_amount_cents,
                        },
                    )
                )
        elif is_cold_start:
            if amount_cents > 500000:  # > $5,000 on unestablished baseline
                raw_factors.append(
                    RiskFactor(
                        name="COLD_START_HIGH_VALUE",
                        category="AMOUNT",
                        score=55.0,
                        weight=1.0,
                        observed_fact=(
                            f"Transfer of ${amount_cents / 100:.2f} requested on profile with "
                            f"{stats.transaction_count} completed transactions (< {self.min_history_transactions} required)."
                        ),
                        inference="Large transfer on an account without established behavioral history warrants step-up review.",
                        description=(
                            f"High initial transaction value (${amount_cents / 100:.2f}) on account with limited baseline history "
                            f"({stats.transaction_count} prior transfers)."
                        ),
                        metadata={"transaction_count": stats.transaction_count, "amount_cents": amount_cents},
                    )
                )

        # ---------------------------------------------------------------------
        # 2. VELOCITY Category Analysis (mutually exclusive 1h vs 24h tiers)
        # ---------------------------------------------------------------------
        cur_1h = conn.execute(
            """SELECT COUNT(*) as cnt, COALESCE(SUM(amount_cents), 0) as total_1h
               FROM simulated_transactions
               WHERE source_account_id = ?
                 AND created_at >= datetime('now', '-1 hour')
                 AND status = 'COMPLETED';""",
            (source_account_id,),
        ).fetchone()
        count_1h = int(cur_1h["cnt"]) if cur_1h else 0

        cur_24h = conn.execute(
            """SELECT COUNT(*) as cnt, COALESCE(SUM(amount_cents), 0) as total_24h
               FROM simulated_transactions
               WHERE source_account_id = ?
                 AND created_at >= datetime('now', '-24 hours')
                 AND status = 'COMPLETED';""",
            (source_account_id,),
        ).fetchone()
        count_24h = int(cur_24h["cnt"]) if cur_24h else 0

        if count_1h >= vel_1h_thresh:
            burst_score = min(85.0, 45.0 + (count_1h * 10.0))
            raw_factors.append(
                RiskFactor(
                    name="RAPID_VELOCITY_BURST_1H",
                    category="VELOCITY",
                    score=round(burst_score, 1),
                    weight=1.0,
                    observed_fact=f"{count_1h} completed outgoing transfers recorded from {source_account_id} in the past 60 minutes.",
                    inference="Abrupt short-horizon transaction frequency spike relative to normal pacing.",
                    description=f"Rapid succession of {count_1h} outgoing transfers within the last hour.",
                    metadata={"count_1h": count_1h, "count_24h": count_24h},
                )
            )
        elif count_24h >= vel_24h_thresh:
            raw_factors.append(
                RiskFactor(
                    name="ELEVATED_DAILY_VELOCITY",
                    category="VELOCITY",
                    score=40.0,
                    weight=1.0,
                    observed_fact=f"{count_24h} completed outgoing transfers recorded from {source_account_id} in the past 24 hours.",
                    inference="Daily transfer frequency is elevated relative to typical baseline pacing.",
                    description=f"Unusually high volume of {count_24h} outgoing transfers in the last 24 hours.",
                    metadata={"count_24h": count_24h},
                )
            )

        # ---------------------------------------------------------------------
        # 3. COUNTERPARTY Category Analysis
        # ---------------------------------------------------------------------
        if destination_account_id not in stats.known_counterparties:
            if not is_cold_start:
                raw_factors.append(
                    RiskFactor(
                        name="NOVEL_COUNTERPARTY",
                        category="COUNTERPARTY",
                        score=35.0,
                        weight=1.0,
                        observed_fact=(
                            f"Destination '{destination_account_id}' has 0 prior completed transfers "
                            f"(account has {len(stats.known_counterparties)} known counterparties)."
                        ),
                        inference="First-time transfer to an unseen recipient for an established profile.",
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
                raw_factors.append(
                    RiskFactor(
                        name="INITIAL_COUNTERPARTY",
                        category="COUNTERPARTY",
                        score=5.0,
                        weight=1.0,
                        observed_fact=f"Destination '{destination_account_id}' observed during cold-start baseline period.",
                        inference="Cold-start profiles naturally establish initial recipients; minimal risk weight applied.",
                        description=f"Establishing transfer relationship with recipient '{destination_account_id}'.",
                        metadata={"destination_account_id": destination_account_id},
                    )
                )
        elif not is_cold_start:
            recipient_count = stats.counterparty_counts.get(destination_account_id, 0)
            if recipient_count == 1 and stats.transaction_count >= 8:
                raw_factors.append(
                    RiskFactor(
                        name="INFREQUENT_COUNTERPARTY",
                        category="COUNTERPARTY",
                        score=15.0,
                        weight=1.0,
                        observed_fact=f"Destination '{destination_account_id}' used only once across {stats.transaction_count} historical transfers.",
                        inference="Infrequently used recipient compared to primary counterparties.",
                        description=f"Recipient '{destination_account_id}' is rarely used (1 of {stats.transaction_count} historical transfers).",
                        metadata={"destination_account_id": destination_account_id, "recipient_count": recipient_count},
                    )
                )

        # ---------------------------------------------------------------------
        # 4. ATTEMPT_PATTERN Category Analysis (Failed / Blocked / Repeated attempts)
        # ---------------------------------------------------------------------
        if stats.recent_failed_or_blocked_count_24h >= failed_thresh:
            fail_score = min(75.0, 35.0 + (stats.recent_failed_or_blocked_count_24h * 10.0))
            raw_factors.append(
                RiskFactor(
                    name="REPEATED_FAILED_OR_BLOCKED_ATTEMPTS",
                    category="ATTEMPT_PATTERN",
                    score=round(fail_score, 1),
                    weight=1.0,
                    observed_fact=f"{stats.recent_failed_or_blocked_count_24h} rejected or firewall-blocked transfer attempts in the last 24 hours.",
                    inference="Multiple recent failed or blocked attempts precede this transaction.",
                    description=(
                        f"User has {stats.recent_failed_or_blocked_count_24h} rejected or blocked transfer attempts "
                        f"within the last 24 hours."
                    ),
                    metadata={"failed_or_blocked_24h": stats.recent_failed_or_blocked_count_24h},
                )
            )
        elif stats.repeated_attempt_count_1h >= 3:
            raw_factors.append(
                RiskFactor(
                    name="REPEATED_TRANSFER_ATTEMPT",
                    category="ATTEMPT_PATTERN",
                    score=30.0,
                    weight=1.0,
                    observed_fact=f"{stats.repeated_attempt_count_1h} identical transfer attempts observed within the last hour.",
                    inference="Repeated identical transfer attempts in a short interval.",
                    description=f"Detected {stats.repeated_attempt_count_1h} repeated transfer attempts with identical parameters in the past hour.",
                    metadata={"repeated_attempt_count_1h": stats.repeated_attempt_count_1h},
                )
            )

        # ---------------------------------------------------------------------
        # 5. TIMING Category Analysis
        # ---------------------------------------------------------------------
        now_utc = datetime.now(timezone.utc)
        current_hour = now_utc.hour
        eval_hour = context.get("simulated_hour_utc", current_hour)
        if context.get("simulated_hour_utc") is not None or not is_cold_start:
            if isinstance(eval_hour, int) and (self.OFF_HOURS_UTC_START <= eval_hour < self.OFF_HOURS_UTC_END):
                raw_factors.append(
                    RiskFactor(
                        name="OFF_HOURS_ACTIVITY",
                        category="TIMING",
                        score=25.0,
                        weight=1.0,
                        observed_fact=f"Transaction timestamp hour is {eval_hour:02d}:00 UTC (window 01:00-05:00 UTC).",
                        inference="Transaction initiated during unusual off-hours window.",
                        description=f"Activity originated during unusual off-hours window ({eval_hour:02d}:00 UTC).",
                        metadata={"hour_utc": eval_hour},
                    )
                )

        # ---------------------------------------------------------------------
        # 6. Deduplicate Correlated Signals by Category & Compute Bounded Score
        # ---------------------------------------------------------------------
        deduped_by_cat: Dict[str, RiskFactor] = {}
        for f in raw_factors:
            existing = deduped_by_cat.get(f.category)
            if existing is None or f.score > existing.score:
                deduped_by_cat[f.category] = f

        factors = sorted(deduped_by_cat.values(), key=lambda x: (-x.score, x.name))

        if not factors:
            composite_score = 5.0
        else:
            sorted_scores = [f.score * f.weight for f in factors]
            primary = sorted_scores[0]
            secondary_sum = sum(sorted_scores[1:])
            # Multi-signal convergence: if >=3 independent significant signals (score >= 20) co-occur
            significant_count = sum(1 for f in factors if f.score >= 20.0)
            convergence_bonus = 10.0 if significant_count >= 3 else 0.0
            composite_score = min(98.0, max(0.0, primary + (secondary_sum * 0.25) + convergence_bonus))

        composite_score = round(composite_score, 1)

        # Map score to RiskLevel, ThreatTier, RecommendedAction, and PolicyRecommendation
        crit_thresh = float(getattr(self.settings, "behavioral_risk_critical_threshold", 75.0))
        high_thresh = float(getattr(self.settings, "behavioral_risk_high_threshold", 50.0))
        med_thresh = float(getattr(self.settings, "behavioral_risk_medium_threshold", 25.0))

        if composite_score >= crit_thresh:
            threat_tier = ThreatTier.CRITICAL_RISK
            risk_level = BehavioralRiskLevel.CRITICAL
            recommended_action = RecommendedAction.DUAL_APPROVAL
            policy_action = PolicyRecommendation.HOLD_FOR_TRUSTED_REVIEW
            recommended_reason = (
                "Critical behavioral anomalies detected across transaction history; "
                "transaction held pending secondary supervisory approval."
            )
        elif composite_score >= high_thresh:
            threat_tier = ThreatTier.HIGH_RISK
            risk_level = BehavioralRiskLevel.HIGH
            recommended_action = RecommendedAction.STEP_UP_AUTH
            policy_action = PolicyRecommendation.REQUIRE_DUAL_APPROVAL
            recommended_reason = (
                "High behavioral risk signals present relative to account baseline; "
                "additional verification or dual approval required."
            )
        elif composite_score >= med_thresh:
            threat_tier = ThreatTier.ELEVATED
            risk_level = BehavioralRiskLevel.MEDIUM
            recommended_action = RecommendedAction.SUPERVISORY_REVIEW
            policy_action = PolicyRecommendation.STEP_UP_REVIEW
            recommended_reason = (
                "Elevated behavioral risk indicators observed; step-up confirmation recommended."
            )
        else:
            threat_tier = ThreatTier.STANDARD
            risk_level = BehavioralRiskLevel.LOW
            recommended_action = RecommendedAction.ALLOW
            policy_action = PolicyRecommendation.ALLOW_UNDER_EXISTING_POLICY
            if is_cold_start:
                recommended_reason = (
                    "Profile has insufficient historical transactions for statistical anomaly detection "
                    f"({stats.transaction_count}/{self.min_history_transactions}); proceeding under standard deterministic controls."
                )
            else:
                recommended_reason = "Transaction aligns with the account's established historical baseline."

        top_explanations = [f.description for f in factors[:4]]
        if not top_explanations:
            top_explanations = [recommended_reason]

        now_iso = datetime.now(timezone.utc).isoformat()
        feature_summary = {
            "transaction_count_30d": stats.transaction_count,
            "mean_amount_cents": stats.mean_amount_cents,
            "median_amount_cents": stats.median_amount_cents,
            "std_amount_cents": stats.std_amount_cents,
            "count_1h": count_1h,
            "count_24h": count_24h,
            "known_counterparties_count": len(stats.known_counterparties),
            "recent_failed_or_blocked_24h": stats.recent_failed_or_blocked_count_24h,
            "profile_status": stats.profile_status.value,
        }

        assessment = RiskAssessment(
            user_id=user_id,
            source_account_id=source_account_id,
            destination_account_id=destination_account_id,
            amount_cents=amount_cents,
            currency=currency,
            transaction_fingerprint=transaction_fingerprint,
            history_watermark=stats.history_watermark,
            timestamp=now_iso,
            assessed_at=now_iso,
            model_version=self.model_version,
            risk_score=composite_score,
            risk_level=risk_level,
            threat_tier=threat_tier,
            profile_status=stats.profile_status,
            confidence=round(confidence, 2),
            factors=factors,
            risk_factors=factors,
            top_explanations=top_explanations,
            explanations=top_explanations,
            recommended_action=recommended_action,
            policy_action=policy_action,
            recommended_action_reason=recommended_reason,
            history_events_analyzed=stats.transaction_count,
            is_cold_start=is_cold_start,
            final_outcome="ASSESSED",
            feature_summary=feature_summary,
        )

        if persist and self._table_exists(conn, "risk_assessments"):
            self.persist_assessment(conn, assessment)

        return assessment

    def persist_assessment(
        self,
        conn: sqlite3.Connection,
        assessment: RiskAssessment,
        record_audit: bool = False,
    ) -> RiskAssessment:
        """Persist a behavioral risk assessment in SQLite and optionally chain to audit_events."""
        if not self._table_exists(conn, "risk_assessments"):
            return assessment

        if record_audit and self._table_exists(conn, "audit_events"):
            audit_store = get_tamper_evident_audit_store()
            event_hash = audit_store.record_audit_event(
                conn=conn,
                event_type="BEHAVIORAL_RISK_ASSESSED",
                principal_id=assessment.user_id,
                decision=f"{assessment.risk_level.value}:{assessment.policy_action.value}",
                transaction_id=assessment.transaction_fingerprint or assessment.assessment_id,
                details={
                    "assessment_id": assessment.assessment_id,
                    "source_account_id": assessment.source_account_id,
                    "destination_account_id": assessment.destination_account_id,
                    "amount_cents": assessment.amount_cents,
                    "risk_score": assessment.risk_score,
                    "risk_level": assessment.risk_level.value,
                    "profile_status": assessment.profile_status.value,
                    "recommended_action": assessment.recommended_action.value,
                    "policy_action": assessment.policy_action.value,
                    "model_version": assessment.model_version,
                },
            )
            assessment.audit_event_hash = event_hash

        factors_json = json.dumps([f.model_dump() for f in assessment.factors], sort_keys=True)
        explanations_json = json.dumps(assessment.explanations)
        summary_json = json.dumps(assessment.feature_summary, sort_keys=True)

        conn.execute(
            """INSERT OR REPLACE INTO risk_assessments (
                assessment_id, user_id, source_account_id, destination_account_id,
                amount_cents, currency, transaction_fingerprint, history_watermark,
                risk_score, risk_level, threat_tier, profile_status, confidence,
                recommended_action, policy_action, recommended_action_reason,
                model_version, history_events_analyzed, is_cold_start,
                factors_json, explanations_json, feature_summary_json,
                assessed_at, final_outcome, audit_event_hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);""",
            (
                assessment.assessment_id,
                assessment.user_id,
                assessment.source_account_id or "UNKNOWN",
                assessment.destination_account_id or "UNKNOWN",
                assessment.amount_cents,
                assessment.currency,
                assessment.transaction_fingerprint,
                assessment.history_watermark,
                assessment.risk_score,
                assessment.risk_level.value,
                assessment.threat_tier.value,
                assessment.profile_status.value,
                assessment.confidence,
                assessment.recommended_action.value,
                assessment.policy_action.value,
                assessment.recommended_action_reason,
                assessment.model_version,
                assessment.history_events_analyzed,
                1 if assessment.is_cold_start else 0,
                factors_json,
                explanations_json,
                summary_json,
                assessment.assessed_at,
                assessment.final_outcome,
                assessment.audit_event_hash,
            ),
        )
        return assessment

    def update_assessment_outcome(
        self,
        conn: sqlite3.Connection,
        assessment_id: Optional[str] = None,
        transaction_fingerprint: Optional[str] = None,
        final_outcome: str = "COMPLETED",
    ) -> None:
        """Update the final transaction outcome on a persisted risk assessment."""
        if not self._table_exists(conn, "risk_assessments"):
            return
        if assessment_id:
            conn.execute(
                "UPDATE risk_assessments SET final_outcome = ? WHERE assessment_id = ?;",
                (final_outcome, assessment_id),
            )
        elif transaction_fingerprint:
            conn.execute(
                "UPDATE risk_assessments SET final_outcome = ? WHERE transaction_fingerprint = ?;",
                (final_outcome, transaction_fingerprint),
            )

    def _row_to_assessment(self, row: sqlite3.Row) -> RiskAssessment:
        factors_raw = json.loads(row["factors_json"] or "[]")
        factors = [RiskFactor(**f) for f in factors_raw]
        explanations = json.loads(row["explanations_json"] or "[]")
        summary = json.loads(row["feature_summary_json"] or "{}")
        return RiskAssessment(
            assessment_id=row["assessment_id"],
            user_id=row["user_id"],
            source_account_id=row["source_account_id"],
            destination_account_id=row["destination_account_id"],
            amount_cents=row["amount_cents"],
            currency=row["currency"],
            transaction_fingerprint=row["transaction_fingerprint"],
            history_watermark=row["history_watermark"],
            timestamp=row["assessed_at"],
            assessed_at=row["assessed_at"],
            model_version=row["model_version"],
            risk_score=row["risk_score"],
            risk_level=BehavioralRiskLevel(row["risk_level"]),
            threat_tier=ThreatTier(row["threat_tier"]),
            profile_status=ProfileStatus(row["profile_status"]),
            confidence=row["confidence"],
            factors=factors,
            risk_factors=factors,
            top_explanations=explanations,
            explanations=explanations,
            recommended_action=RecommendedAction(row["recommended_action"]),
            policy_action=PolicyRecommendation(row["policy_action"]),
            recommended_action_reason=row["recommended_action_reason"],
            history_events_analyzed=row["history_events_analyzed"],
            is_cold_start=bool(row["is_cold_start"]),
            final_outcome=row["final_outcome"],
            audit_event_hash=row["audit_event_hash"],
            feature_summary=summary,
        )

    def get_user_assessments(
        self,
        conn: sqlite3.Connection,
        user_id: str,
        account_id: Optional[str] = None,
        limit: int = 20,
        offset: int = 0,
    ) -> Tuple[List[RiskAssessment], int]:
        """Retrieve bounded, paginated risk assessment history for an authenticated user."""
        if not self._table_exists(conn, "risk_assessments"):
            return [], 0

        safe_limit = max(1, min(int(limit), 100))
        safe_offset = max(0, int(offset))

        where_sql = "WHERE user_id = ?"
        params: List[Any] = [user_id]
        if account_id:
            where_sql += " AND source_account_id = ?"
            params.append(account_id)

        total_row = conn.execute(
            f"SELECT COUNT(*) as cnt FROM risk_assessments {where_sql};",
            params,
        ).fetchone()
        total = int(total_row["cnt"]) if total_row else 0

        rows = conn.execute(
            f"""SELECT * FROM risk_assessments
                {where_sql}
                ORDER BY assessed_at DESC, rowid DESC
                LIMIT ? OFFSET ?;""",
            params + [safe_limit, safe_offset],
        ).fetchall()

        return [self._row_to_assessment(r) for r in rows], total

    def get_assessment_by_id(
        self,
        conn: sqlite3.Connection,
        assessment_id: str,
    ) -> Optional[RiskAssessment]:
        """Fetch a single persisted risk assessment by ID."""
        if not self._table_exists(conn, "risk_assessments"):
            return None
        row = conn.execute(
            "SELECT * FROM risk_assessments WHERE assessment_id = ?;",
            (assessment_id,),
        ).fetchone()
        if not row:
            return None
        return self._row_to_assessment(row)

    def get_assessment_by_fingerprint(
        self,
        conn: sqlite3.Connection,
        transaction_fingerprint: str,
    ) -> Optional[RiskAssessment]:
        """Fetch the latest assessment bound to a canonical transaction fingerprint."""
        if not self._table_exists(conn, "risk_assessments"):
            return None
        row = conn.execute(
            """SELECT * FROM risk_assessments
               WHERE transaction_fingerprint = ?
               ORDER BY assessed_at DESC, rowid DESC LIMIT 1;""",
            (transaction_fingerprint,),
        ).fetchone()
        if not row:
            return None
        return self._row_to_assessment(row)

    def get_user_profile(
        self,
        conn: sqlite3.Connection,
        user_id: str,
        username: str,
        account_id: Optional[str] = None,
    ) -> UserProfileResponse:
        """Retrieve aggregated behavioral threat profile for an authenticated user."""
        stats = self.get_historical_stats(
            conn,
            user_id=user_id,
            account_id=account_id,
            days_window=getattr(self.settings, "behavioral_window_days", 30),
        )

        active_factors: List[RiskFactor] = []
        base_score = 10.0

        vel_24h_thresh = int(getattr(self.settings, "velocity_daily_burst_threshold", self.VELOCITY_DAILY_BURST_THRESHOLD))
        failed_thresh = int(getattr(self.settings, "repeated_failed_attempts_threshold", self.REPEATED_FAILED_ATTEMPTS_THRESHOLD))

        if stats.count_24h >= vel_24h_thresh:
            active_factors.append(
                RiskFactor(
                    name="ACTIVE_HIGH_VELOCITY",
                    category="VELOCITY",
                    score=40.0,
                    observed_fact=f"{stats.count_24h} completed transactions in the past 24 hours.",
                    inference="Elevated daily transaction frequency on this profile.",
                    description=f"{stats.count_24h} transactions initiated in the past 24 hours.",
                )
            )
            base_score += 35.0

        if stats.recent_failed_or_blocked_count_24h >= failed_thresh:
            active_factors.append(
                RiskFactor(
                    name="RECENT_REJECTED_OR_BLOCKED_ACTIVITY",
                    category="ATTEMPT_PATTERN",
                    score=35.0,
                    observed_fact=f"{stats.recent_failed_or_blocked_count_24h} failed or blocked attempts in the past 24 hours.",
                    inference="Multiple recent rejected or blocked transfer attempts recorded.",
                    description=f"{stats.recent_failed_or_blocked_count_24h} rejected or blocked attempts in the past 24 hours.",
                )
            )
            base_score += 30.0

        if stats.profile_status == ProfileStatus.INSUFFICIENT_HISTORY:
            active_factors.append(
                RiskFactor(
                    name="INSUFFICIENT_HISTORY_BASELINE",
                    category="COLD_START",
                    score=15.0,
                    observed_fact=f"Profile has {stats.transaction_count} completed transactions (< {self.min_history_transactions} minimum).",
                    inference="Statistical anomaly baseline is not yet established; deterministic transaction controls apply.",
                    description=(
                        f"Insufficient transaction history ({stats.transaction_count}/{self.min_history_transactions} "
                        "completed transfers) to establish full statistical baseline."
                    ),
                )
            )
            if stats.transaction_count == 0:
                base_score += 10.0
            else:
                base_score += 5.0

        recent_assessments, _ = self.get_user_assessments(conn, user_id=user_id, account_id=account_id, limit=10)
        if recent_assessments:
            max_recent = max(a.risk_score for a in recent_assessments[:3])
            base_score = max(base_score, round(max_recent * 0.6, 1))

        current_score = min(100.0, round(base_score, 1))

        if current_score >= 75.0:
            tier = ThreatTier.CRITICAL_RISK
            r_level = BehavioralRiskLevel.CRITICAL
        elif current_score >= 50.0:
            tier = ThreatTier.HIGH_RISK
            r_level = BehavioralRiskLevel.HIGH
        elif current_score >= 25.0:
            tier = ThreatTier.ELEVATED
            r_level = BehavioralRiskLevel.MEDIUM
        else:
            tier = ThreatTier.STANDARD
            r_level = BehavioralRiskLevel.LOW

        explanations = [f.description for f in active_factors] or [
            "Account behavioral profile is established and operating within expected historical norms."
        ]

        return UserProfileResponse(
            user_id=user_id,
            username=username,
            profile_status=stats.profile_status,
            risk_level=r_level,
            threat_tier=tier,
            current_risk_score=current_score,
            model_version=self.model_version,
            total_transactions_analyzed=stats.transaction_count,
            known_counterparties_count=len(stats.known_counterparties),
            recent_failed_attempts_24h=stats.recent_failed_or_blocked_count_24h,
            last_assessed_at=datetime.now(timezone.utc).isoformat(),
            active_risk_factors=active_factors,
            explanations=explanations,
            historical_stats=stats,
            recent_assessments=recent_assessments,
            feature_limitations=dict(FEATURE_LIMITATIONS_DOC),
        )


_risk_engine_instance: Optional[BehavioralRiskEngine] = None


def get_behavioral_risk_engine() -> BehavioralRiskEngine:
    global _risk_engine_instance
    if _risk_engine_instance is None:
        _risk_engine_instance = BehavioralRiskEngine()
    return _risk_engine_instance
