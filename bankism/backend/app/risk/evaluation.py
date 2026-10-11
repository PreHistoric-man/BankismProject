"""Phase 3.8 Reproducible Synthetic Evaluation & Calibration Benchmark.

Evaluates the deterministic BehavioralRiskEngine across 8 synthetic scenario families
using fixed random seeds (`random.Random(42)`) and isolated temporary SQLite state.

IMPORTANT DISCLAIMER:
Results produced by this benchmark represent synthetic scenario-test alignment
against the configured Phase 3 scoring policy. They do NOT represent production
fraud-detection accuracy or calibrated real-world probability of criminality.
"""

import os
import random
import tempfile
from typing import Any, Dict, List
from ..ledger.db import get_db_connection, init_ledger_database
from ..profiling.engine import BehavioralRiskEngine
from ..schemas.profiling import BehavioralRiskLevel, ProfileStatus


def run_synthetic_calibration_suite(seed: int = 42) -> Dict[str, Any]:
    """Run reproducible synthetic evaluation across 8 scenario archetypes."""
    rng = random.Random(seed)
    fd, db_path = tempfile.mkstemp(suffix="_eval.db")
    os.close(fd)

    try:
        init_ledger_database(db_path)
        engine = BehavioralRiskEngine()
        results: List[Dict[str, Any]] = []

        with get_db_connection(db_path) as conn:
            # Create dedicated synthetic users & accounts for clean scenario isolation
            scenarios_setup = [
                ("USR-SYN-01", "syn_normal", "ACC-SYN-01"),
                ("USR-SYN-02", "syn_large_legit", "ACC-SYN-02"),
                ("USR-SYN-03", "syn_new_recip", "ACC-SYN-03"),
                ("USR-SYN-04", "syn_freq_burst", "ACC-SYN-04"),
                ("USR-SYN-05", "syn_failed_attempts", "ACC-SYN-05"),
                ("USR-SYN-06", "syn_sparse_cold", "ACC-SYN-06"),
                ("USR-SYN-07", "syn_seasonal", "ACC-SYN-07"),
                ("USR-SYN-08", "syn_mixed_conflict", "ACC-SYN-08"),
            ]
            for uid, uname, acc_id in scenarios_setup:
                conn.execute(
                    "INSERT OR IGNORE INTO fictional_users (user_id, username, role) VALUES (?, ?, 'CUSTOMER');",
                    (uid, uname),
                )
                conn.execute(
                    """INSERT OR IGNORE INTO accounts
                       (account_id, user_id, account_name, account_type, balance_cents, currency, daily_limit_cents, is_active)
                       VALUES (?, ?, ?, 'CHECKING', 9000000, 'USD', 5000000, 1);""",
                    (acc_id, uid, f"{uname} Checking"),
                )

            # 1. Stable normal activity (Expected: LOW risk, ESTABLISHED)
            for i in range(8):
                amt = 10000 + rng.randint(-1500, 1500)  # ~$100 +/- $15
                conn.execute(
                    """INSERT INTO simulated_transactions
                       (transaction_id, idempotency_key, source_account_id, destination_account_id, amount_cents, status, created_at)
                       VALUES (?, ?, 'ACC-SYN-01', 'ACC-2002-SAV', ?, 'COMPLETED', datetime('now', ?));""",
                    (f"syn1_{i}", f"idem1_{i}", amt, f"-{i + 2} days"),
                )
            a1 = engine.assess_transaction_risk(
                conn, "USR-SYN-01", "ACC-SYN-01", "ACC-2002-SAV", 10500
            )
            results.append({
                "scenario_id": "SCEN-01",
                "name": "Stable Normal Activity",
                "expected_elevated_or_higher": False,
                "expected_factors": [],
                "actual_score": a1.risk_score,
                "actual_level": a1.risk_level.value,
                "profile_status": a1.profile_status.value,
                "triggered_factors": [f.name for f in a1.factors],
                "recommended_action": a1.policy_action.value,
            })

            # 2. Legitimate occasional large transfer (Expected: Flagged for review due to 15x spike)
            for i in range(6):
                conn.execute(
                    """INSERT INTO simulated_transactions
                       (transaction_id, idempotency_key, source_account_id, destination_account_id, amount_cents, status, created_at)
                       VALUES (?, ?, 'ACC-SYN-02', 'ACC-2002-SAV', 12000, 'COMPLETED', datetime('now', ?));""",
                    (f"syn2_{i}", f"idem2_{i}", f"-{i + 3} days"),
                )
            a2 = engine.assess_transaction_risk(
                conn, "USR-SYN-02", "ACC-SYN-02", "ACC-2002-SAV", 180000  # $1,800 vs $120 mean (15x)
            )
            results.append({
                "scenario_id": "SCEN-02",
                "name": "Occasional Large Transfer (15x Baseline)",
                "expected_elevated_or_higher": True,
                "expected_factors": ["AMOUNT_SPIKE_ANOMALY"],
                "actual_score": a2.risk_score,
                "actual_level": a2.risk_level.value,
                "profile_status": a2.profile_status.value,
                "triggered_factors": [f.name for f in a2.factors],
                "recommended_action": a2.policy_action.value,
            })

            # 3. New recipient with normal amount (Expected: MEDIUM / ELEVATED, not auto-blocked)
            for i in range(5):
                conn.execute(
                    """INSERT INTO simulated_transactions
                       (transaction_id, idempotency_key, source_account_id, destination_account_id, amount_cents, status, created_at)
                       VALUES (?, ?, 'ACC-SYN-03', 'ACC-2002-SAV', 15000, 'COMPLETED', datetime('now', ?));""",
                    (f"syn3_{i}", f"idem3_{i}", f"-{i + 2} days"),
                )
            a3 = engine.assess_transaction_risk(
                conn, "USR-SYN-03", "ACC-SYN-03", "ACC-3003-BUS", 15000
            )
            results.append({
                "scenario_id": "SCEN-03",
                "name": "Established User Paying New Recipient (Normal Amount)",
                "expected_elevated_or_higher": True,
                "expected_factors": ["NOVEL_COUNTERPARTY"],
                "actual_score": a3.risk_score,
                "actual_level": a3.risk_level.value,
                "profile_status": a3.profile_status.value,
                "triggered_factors": [f.name for f in a3.factors],
                "recommended_action": a3.policy_action.value,
            })

            # 4. Sudden increase in frequency / 1h velocity burst
            for i in range(4):
                conn.execute(
                    """INSERT INTO simulated_transactions
                       (transaction_id, idempotency_key, source_account_id, destination_account_id, amount_cents, status, created_at)
                       VALUES (?, ?, 'ACC-SYN-04', 'ACC-2002-SAV', 8000, 'COMPLETED', datetime('now', '-15 minutes'));""",
                    (f"syn4_{i}", f"idem4_{i}"),
                )
            a4 = engine.assess_transaction_risk(
                conn, "USR-SYN-04", "ACC-SYN-04", "ACC-2002-SAV", 8000
            )
            results.append({
                "scenario_id": "SCEN-04",
                "name": "Sudden Frequency Burst (4 Transfers in 15m)",
                "expected_elevated_or_higher": True,
                "expected_factors": ["RAPID_VELOCITY_BURST_1H"],
                "actual_score": a4.risk_score,
                "actual_level": a4.risk_level.value,
                "profile_status": a4.profile_status.value,
                "triggered_factors": [f.name for f in a4.factors],
                "recommended_action": a4.policy_action.value,
            })

            # 5. Repeated failed / blocked attempts preceding transfer
            for i in range(4):
                conn.execute(
                    """INSERT INTO simulated_transactions
                       (transaction_id, idempotency_key, source_account_id, destination_account_id, amount_cents, status, created_at)
                       VALUES (?, ?, 'ACC-SYN-05', 'ACC-2002-SAV', 9000, 'COMPLETED', datetime('now', ?));""",
                    (f"syn5_{i}", f"idem5_{i}", f"-{i + 3} days"),
                )
            for j in range(3):
                engine.record_transfer_attempt(
                    conn, "USR-SYN-05", "ACC-SYN-05", "ACC-2002-SAV", 9000, "BLOCKED_FIREWALL", reason="Simulated block"
                )
            a5 = engine.assess_transaction_risk(
                conn, "USR-SYN-05", "ACC-SYN-05", "ACC-2002-SAV", 9000
            )
            results.append({
                "scenario_id": "SCEN-05",
                "name": "Repeated Failed/Blocked Attempts Followed by Valid Transfer",
                "expected_elevated_or_higher": True,
                "expected_factors": ["REPEATED_FAILED_OR_BLOCKED_ATTEMPTS"],
                "actual_score": a5.risk_score,
                "actual_level": a5.risk_level.value,
                "profile_status": a5.profile_status.value,
                "triggered_factors": [f.name for f in a5.factors],
                "recommended_action": a5.policy_action.value,
            })

            # 6. Sparse history / cold-start routine transfer (Expected: INSUFFICIENT_HISTORY, LOW risk, not blocked)
            conn.execute(
                """INSERT INTO simulated_transactions
                   (transaction_id, idempotency_key, source_account_id, destination_account_id, amount_cents, status, created_at)
                   VALUES ('syn6_0', 'idem6_0', 'ACC-SYN-06', 'ACC-2002-SAV', 5000, 'COMPLETED', datetime('now', '-5 days'));"""
            )
            a6 = engine.assess_transaction_risk(
                conn, "USR-SYN-06", "ACC-SYN-06", "ACC-3003-BUS", 4500
            )
            results.append({
                "scenario_id": "SCEN-06",
                "name": "Sparse History / Cold-Start Routine Transfer",
                "expected_elevated_or_higher": False,
                "expected_factors": ["INITIAL_COUNTERPARTY"],
                "actual_score": a6.risk_score,
                "actual_level": a6.risk_level.value,
                "profile_status": a6.profile_status.value,
                "triggered_factors": [f.name for f in a6.factors],
                "recommended_action": a6.policy_action.value,
            })

            # 7. Seasonal / naturally varying behavior (wider historical std dev accommodates moderate variation)
            seasonal_amounts = [20000, 45000, 80000, 35000, 90000, 60000]
            for i, s_amt in enumerate(seasonal_amounts):
                conn.execute(
                    """INSERT INTO simulated_transactions
                       (transaction_id, idempotency_key, source_account_id, destination_account_id, amount_cents, status, created_at)
                       VALUES (?, ?, 'ACC-SYN-07', 'ACC-2002-SAV', ?, 'COMPLETED', datetime('now', ?));""",
                    (f"syn7_{i}", f"idem7_{i}", s_amt, f"-{i + 2} days"),
                )
            a7 = engine.assess_transaction_risk(
                conn, "USR-SYN-07", "ACC-SYN-07", "ACC-2002-SAV", 95000  # Within < 2x mean and < 2.0 z-score
            )
            results.append({
                "scenario_id": "SCEN-07",
                "name": "Seasonal / High-Variance Baseline with Moderate Transfer",
                "expected_elevated_or_higher": False,
                "expected_factors": [],
                "actual_score": a7.risk_score,
                "actual_level": a7.risk_level.value,
                "profile_status": a7.profile_status.value,
                "triggered_factors": [f.name for f in a7.factors],
                "recommended_action": a7.policy_action.value,
            })

            # 8. Mixed-risk converging signals (Amount spike + Novel counterparty + Off-hours)
            for i in range(5):
                conn.execute(
                    """INSERT INTO simulated_transactions
                       (transaction_id, idempotency_key, source_account_id, destination_account_id, amount_cents, status, created_at)
                       VALUES (?, ?, 'ACC-SYN-08', 'ACC-2002-SAV', 10000, 'COMPLETED', datetime('now', ?));""",
                    (f"syn8_{i}", f"idem8_{i}", f"-{i + 3} days"),
                )
            a8 = engine.assess_transaction_risk(
                conn,
                "USR-SYN-08",
                "ACC-SYN-08",
                "ACC-4004-CHK",
                120000,
                context={"simulated_hour_utc": 3},
            )
            results.append({
                "scenario_id": "SCEN-08",
                "name": "Multi-Signal Convergence (Amount Spike + Novel Recipient + Off-Hours)",
                "expected_elevated_or_higher": True,
                "expected_factors": ["AMOUNT_SPIKE_ANOMALY", "NOVEL_COUNTERPARTY", "OFF_HOURS_ACTIVITY"],
                "actual_score": a8.risk_score,
                "actual_level": a8.risk_level.value,
                "profile_status": a8.profile_status.value,
                "triggered_factors": [f.name for f in a8.factors],
                "recommended_action": a8.policy_action.value,
            })

        # Compute scenario confusion metrics against synthetic labels
        true_positives = 0
        true_negatives = 0
        false_positives = 0
        false_negatives = 0

        for r in results:
            is_flagged = r["actual_level"] in (
                BehavioralRiskLevel.MEDIUM.value,
                BehavioralRiskLevel.HIGH.value,
                BehavioralRiskLevel.CRITICAL.value,
            )
            if r["expected_elevated_or_higher"] and is_flagged:
                true_positives += 1
            elif not r["expected_elevated_or_higher"] and not is_flagged:
                true_negatives += 1
            elif not r["expected_elevated_or_higher"] and is_flagged:
                false_positives += 1
            else:
                false_negatives += 1

        return {
            "seed": seed,
            "model_version": engine.model_version,
            "total_scenarios": len(results),
            "true_positives": true_positives,
            "true_negatives": true_negatives,
            "false_positives": false_positives,
            "false_negatives": false_negatives,
            "scenarios": results,
            "disclaimer": (
                "Synthetic scenario-test evaluation only. Counts measure alignment against "
                "deterministic scenario expectations, NOT real-world fraud detection accuracy."
            ),
        }
    finally:
        if os.path.exists(db_path):
            os.remove(db_path)
