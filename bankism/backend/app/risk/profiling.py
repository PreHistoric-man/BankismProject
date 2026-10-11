"""
Deterministic Behavioral Risk Intelligence & Profiling Engine
"""
import math
import sqlite3
import json
import uuid
from typing import List, Dict, Any, Tuple, Optional
from datetime import datetime, timezone, timedelta
from ..config import settings
from ..schemas.common import RiskLevel, ProfileStatus, BehavioralPolicyAction, Verdict
from ..schemas.responses import BehavioralAssessmentResponse, BehavioralRiskFactor


def compute_user_profile(conn: sqlite3.Connection, user_id: str, username: str) -> Dict[str, Any]:
    """
    Computes statistical baseline strictly from trusted server-side completed transactions.
    """
    # 1. Fetch completed historical transactions
    cur = conn.execute(
        "SELECT amount_cents, destination_account_id, created_at_utc FROM simulated_transactions WHERE user_id = ? AND status = 'COMPLETED' ORDER BY created_at_utc ASC;",
        (user_id,)
    )
    rows = cur.fetchall()
    tx_count = len(rows)
    amounts = sorted([r["amount_cents"] for r in rows])

    # 2. Determine profile status (cold-start vs established)
    is_cold_start = tx_count < settings.min_history_transactions
    profile_status = ProfileStatus.INSUFFICIENT_HISTORY if is_cold_start else ProfileStatus.ESTABLISHED

    # 3. Central tendency & dispersion
    mean_cents = round(sum(amounts) / tx_count) if tx_count > 0 else 0
    if tx_count == 0:
        median_cents = 0
    elif tx_count % 2 == 1:
        median_cents = amounts[tx_count // 2]
    else:
        median_cents = round((amounts[tx_count // 2 - 1] + amounts[tx_count // 2]) / 2)

    variance = (sum((x - mean_cents) ** 2 for x in amounts) / (tx_count - 1)) if tx_count > 1 else 0
    std_cents = round(math.sqrt(variance))
    max_cents = amounts[-1] if tx_count > 0 else 0

    known_counterparties = sorted(list({r["destination_account_id"] for r in rows}))

    # 4. Multi-window velocity counts
    # In SQLite, parse created_at_utc timestamps
    now = datetime.now(timezone.utc)
    one_hour_ago = now - timedelta(hours=1)
    twenty_four_hours_ago = now - timedelta(hours=24)

    cur_attempts = conn.execute(
        "SELECT COUNT(*) as cnt FROM transfer_attempts WHERE user_id = ? AND status != 'COMPLETED';",
        (user_id,)
    )
    failed_row = cur_attempts.fetchone()
    failed_24h = failed_row["cnt"] if failed_row else 0

    # For testing, we calculate 1h velocity count from rows with recent timestamps
    count_1h = 0
    count_24h = 0
    for r in rows:
        try:
            dt = datetime.fromisoformat(r["created_at_utc"].replace("Z", "+00:00"))
            if dt >= one_hour_ago:
                count_1h += 1
            if dt >= twenty_four_hours_ago:
                count_24h += 1
        except Exception:
            pass

    history_watermark = f"wm_{user_id}_{tx_count}_{count_1h}_{failed_24h}"

    return {
        "user_id": user_id,
        "username": username,
        "profile_status": profile_status,
        "transaction_count": tx_count,
        "count_1h": count_1h,
        "count_24h": count_24h,
        "failed_24h": failed_24h,
        "mean_dollars": mean_cents / 100.0,
        "median_dollars": median_cents / 100.0,
        "std_dollars": std_cents / 100.0,
        "max_dollars": max_cents / 100.0,
        "mean_cents": mean_cents,
        "median_cents": median_cents,
        "std_cents": std_cents,
        "known_counterparties": known_counterparties,
        "history_watermark": history_watermark,
    }


def assess_transaction_risk(
    conn: sqlite3.Connection,
    user_id: str,
    username: str,
    src: str,
    dst: str,
    amount_cents: int,
    fw_verdict: Verdict,
    off_hours: bool = False
) -> BehavioralAssessmentResponse:
    """
    Evaluates explainable behavioral risk across orthogonal categories with deduplication.
    """
    profile = compute_user_profile(conn, user_id, username)
    is_cold_start = profile["profile_status"] == ProfileStatus.INSUFFICIENT_HISTORY
    mean_cents = profile["mean_cents"]
    std_cents = profile["std_cents"]
    known_counterparties = set(profile["known_counterparties"])
    tx_count = profile["transaction_count"]
    count_1h = profile["count_1h"]
    failed_24h = profile["failed_24h"]

    factors_by_category: Dict[str, BehavioralRiskFactor] = {}

    amount_dollars = amount_cents / 100.0

    # 1. AMOUNT Category
    if not is_cold_start and mean_cents > 0:
        ratio = amount_cents / mean_cents
        z_score = ((amount_cents - mean_cents) / std_cents) if std_cents > 0 else (ratio - 1.0) * 2.0
        if z_score >= settings.amount_spike_z_score_threshold or ratio >= settings.amount_spike_ratio_threshold:
            score = min(90.0, round((40.0 + ratio * 10.0 + max(0.0, z_score) * 8.0) * 10) / 10)
            factor = BehavioralRiskFactor(
                name="AMOUNT_SPIKE_ANOMALY",
                category="AMOUNT",
                score=score,
                observed_fact=f"Amount ${amount_dollars:,.2f} is {ratio:.1f}x the historical mean (${mean_cents/100:,.2f}) [z-score: {z_score:.2f}].",
                inference="Transfer size deviates substantially above the established baseline for this account.",
                description=f"Proposed amount (${amount_dollars:,.2f}) is {ratio:.1f}x historical mean."
            )
            factors_by_category["AMOUNT"] = factor
    elif is_cold_start and amount_cents > 500000:  # > $5,000 on cold start
        factors_by_category["AMOUNT"] = BehavioralRiskFactor(
            name="COLD_START_HIGH_VALUE",
            category="AMOUNT",
            score=55.0,
            observed_fact=f"Transfer of ${amount_dollars:,.2f} requested on cold-start profile ({tx_count}/3 historical transfers).",
            inference="Large transfer without established historical baseline warrants supervisory review.",
            description=f"High initial transfer (${amount_dollars:,.2f}) on unestablished profile."
        )

    # 2. VELOCITY Category
    if count_1h >= settings.velocity_hourly_burst_threshold:
        v_score = min(85.0, 45.0 + count_1h * 10.0)
        factors_by_category["VELOCITY"] = BehavioralRiskFactor(
            name="RAPID_VELOCITY_BURST_1H",
            category="VELOCITY",
            score=v_score,
            observed_fact=f"{count_1h} completed outgoing transfers recorded within the last 60 minutes.",
            inference="Abrupt short-horizon transaction frequency spike compared to historical pacing.",
            description=f"Rapid burst of {count_1h} outgoing transfers in the past hour."
        )

    # 3. COUNTERPARTY Category
    if dst not in known_counterparties:
        if not is_cold_start:
            factors_by_category["COUNTERPARTY"] = BehavioralRiskFactor(
                name="NOVEL_COUNTERPARTY",
                category="COUNTERPARTY",
                score=35.0,
                observed_fact=f"Destination '{dst}' has 0 prior completed transfers out of {len(known_counterparties)} known recipients.",
                inference="First-time recipient for an established account profile.",
                description=f"Recipient '{dst}' has not been transacted with previously."
            )
        else:
            factors_by_category["COUNTERPARTY"] = BehavioralRiskFactor(
                name="INITIAL_COUNTERPARTY",
                category="COUNTERPARTY",
                score=5.0,
                observed_fact=f"Destination '{dst}' observed during cold-start baseline period.",
                inference="New accounts naturally establish initial recipients; minimal risk contribution.",
                description=f"Establishing initial transfer relationship with '{dst}' (cold start)."
            )

    # 4. ATTEMPTS Category
    if failed_24h >= settings.repeated_failed_attempts_threshold:
        f_score = min(75.0, 35.0 + failed_24h * 10.0)
        factors_by_category["ATTEMPTS"] = BehavioralRiskFactor(
            name="REPEATED_FAILED_ATTEMPTS",
            category="ATTEMPTS",
            score=f_score,
            observed_fact=f"{failed_24h} rejected or firewall-blocked transfer attempts recorded in the past 24 hours.",
            inference="Multiple recent failed or blocked attempts precede this request.",
            description=f"User has {failed_24h} rejected or blocked attempts in the last 24 hours."
        )

    # 5. TIMING Category
    if off_hours:
        factors_by_category["TIMING"] = BehavioralRiskFactor(
            name="OFF_HOURS_ACTIVITY",
            category="TIMING",
            score=25.0,
            observed_fact="Transaction initiated during 01:00-05:00 UTC off-hours window.",
            inference="Unusual transaction timing relative to standard operating hours.",
            description="Activity originated during unusual off-hours window (03:00 UTC)."
        )

    # Orthogonal Category Deduplication: only highest score per category counts
    sorted_factors = sorted(factors_by_category.values(), key=lambda f: f.score, reverse=True)
    composite_score = 5.0

    if sorted_factors:
        primary = sorted_factors[0].score
        secondary_sum = sum(f.score for f in sorted_factors[1:])
        sig_count = sum(1 for f in sorted_factors if f.score >= 20.0)
        convergence_bonus = 15.0 if sig_count >= 3 else (8.0 if sig_count >= 2 else 0.0)
        composite_score = min(98.0, round((primary + secondary_sum * 0.25 + convergence_bonus) * 10) / 10)

    # Policy mapping
    if composite_score >= settings.behavioral_risk_critical_threshold:
        risk_level = RiskLevel.CRITICAL
        policy_action = BehavioralPolicyAction.HOLD_FOR_TRUSTED_REVIEW
        reason = "Critical behavioral deviation detected; held pending secondary Risk Officer approval."
    elif composite_score >= settings.behavioral_risk_high_threshold:
        risk_level = RiskLevel.HIGH
        policy_action = BehavioralPolicyAction.REQUIRE_DUAL_APPROVAL
        reason = "High behavioral anomaly score relative to baseline; escalated to Dual Approval workflow."
    elif composite_score >= settings.behavioral_risk_medium_threshold:
        risk_level = RiskLevel.MEDIUM
        policy_action = BehavioralPolicyAction.STEP_UP_REVIEW
        reason = "Moderate behavioral novelty (e.g., new recipient); step-up review recorded."
    else:
        risk_level = RiskLevel.LOW
        policy_action = BehavioralPolicyAction.ALLOW_UNDER_EXISTING_POLICY
        if is_cold_start:
            reason = f"Insufficient historical baseline ({tx_count}/3 transfers); governed by deterministic controls without false blocking."
        else:
            reason = "Transaction aligns with the authenticated user's observed historical baseline."

    assessment_id = f"ras_{uuid.uuid4().hex[:10]}"
    tx_fingerprint = f"fp_{uuid.uuid4().hex[:14]}"
    now_iso = datetime.now(timezone.utc).isoformat()
    confidence = 0.35 if is_cold_start else min(1.0, round((tx_count / 10.0) * 100) / 100)

    final_outcome = (
        "BLOCKED_FIREWALL" if fw_verdict == Verdict.BLOCK
        else ("PENDING_DUAL_APPROVAL" if composite_score >= settings.behavioral_risk_high_threshold else "AUTHORIZED")
    )

    assessment = BehavioralAssessmentResponse(
        assessment_id=assessment_id,
        user_id=user_id,
        username=username,
        source_account_id=src,
        destination_account_id=dst,
        amount_cents=amount_cents,
        currency="USD",
        transaction_fingerprint=tx_fingerprint,
        history_watermark=profile["history_watermark"],
        risk_score=composite_score,
        risk_level=risk_level,
        profile_status=profile["profile_status"],
        confidence=confidence,
        risk_factors=sorted_factors,
        explanations=[f.description for f in sorted_factors] if sorted_factors else [reason],
        policy_action=policy_action,
        recommended_action_reason=reason,
        model_version=settings.behavioral_policy_version,
        assessed_at=now_iso,
        final_outcome=final_outcome,
        firewall_verdict=fw_verdict,
    )

    # Persist in SQLite
    factors_json = json.dumps([f.model_dump() for f in sorted_factors])
    conn.execute(
        """INSERT INTO risk_assessments 
        (assessment_id, user_id, source_account_id, destination_account_id, amount_cents, currency, risk_score, risk_level, profile_status, policy_action, factors_json, history_watermark, created_at_utc)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);""",
        (
            assessment_id, user_id, src, dst, amount_cents, "USD",
            composite_score, risk_level.value, profile["profile_status"].value,
            policy_action.value, factors_json, profile["history_watermark"], now_iso
        )
    )

    return assessment
