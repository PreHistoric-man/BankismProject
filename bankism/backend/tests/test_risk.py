"""
Behavioral Risk Intelligence & Threat Profiling Tests
"""
from app.risk.profiling import compute_user_profile, assess_transaction_risk
from app.schemas.common import Verdict, ProfileStatus, RiskLevel


def test_cold_start_profile(client):
    headers = {"X-Bankism-Mock-User": "dave"}
    res = client.get("/banking/risk/profile", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert data["profile_status"] == "INSUFFICIENT_HISTORY"
    assert data["transaction_count"] < 3


def test_established_profile(client):
    headers = {"X-Bankism-Mock-User": "alice"}
    res = client.get("/banking/risk/profile", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert data["profile_status"] == "ESTABLISHED"
    assert data["transaction_count"] >= 3
    assert data["mean_dollars"] > 0


def test_risk_assessment_amount_spike(db_conn):
    # Alice transferring $2,500 (25x her ~$100 mean)
    assessment = assess_transaction_risk(
        conn=db_conn,
        user_id="USR-4401-ALICE",
        username="alice",
        src="ACC-1001-CHK",
        dst="ACC-2002-SAV",
        amount_cents=250000,
        fw_verdict=Verdict.APPROVE
    )
    assert assessment.risk_score >= 75.0
    assert assessment.risk_level == RiskLevel.CRITICAL
    assert assessment.policy_action.value == "HOLD_FOR_TRUSTED_REVIEW"
    assert any(f.name == "AMOUNT_SPIKE_ANOMALY" for f in assessment.risk_factors)


def test_risk_assessment_novel_counterparty(db_conn):
    # Alice transferring $110 to unseen recipient
    assessment = assess_transaction_risk(
        conn=db_conn,
        user_id="USR-4401-ALICE",
        username="alice",
        src="ACC-1001-CHK",
        dst="ACC-9999-NEW",
        amount_cents=11000,
        fw_verdict=Verdict.APPROVE
    )
    assert assessment.risk_score >= 25.0
    assert assessment.policy_action.value in ("STEP_UP_REVIEW", "REQUIRE_DUAL_APPROVAL")
    assert any(f.name == "NOVEL_COUNTERPARTY" for f in assessment.risk_factors)


def test_cross_user_assessment_isolation(client, db_conn):
    # Create an assessment for Bob
    bob_assessment = assess_transaction_risk(
        conn=db_conn,
        user_id="USR-8899-BOB",
        username="bob",
        src="ACC-3003-BUS",
        dst="ACC-1001-CHK",
        amount_cents=150000,
        fw_verdict=Verdict.APPROVE
    )
    db_conn.commit()

    # Alice attempts to fetch Bob's assessment by ID -> 403 Forbidden
    alice_headers = {"X-Bankism-Mock-User": "alice"}
    res = client.get(f"/banking/risk/assessments/{bob_assessment.assessment_id}", headers=alice_headers)
    assert res.status_code == 403
    assert "ACCESS_DENIED" in res.json()["detail"]
