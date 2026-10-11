"""
Authorization & Dual Approval Tests
"""
from app.authorization.tickets import sign_canonical_tx, verify_ticket_integrity
from app.schemas.requests import CanonicalTransactionPayload, AuthorizationTicketModel


def test_hmac_tamper_detection():
    canonical = CanonicalTransactionPayload(
        transaction_nonce="nonce_test_01",
        initiator_user_id="USR-4401-ALICE",
        source_account_id="ACC-1001-CHK",
        destination_account_id="ACC-2002-SAV",
        amount_cents=10000,
        currency="USD"
    )
    sig = sign_canonical_tx(canonical)
    ticket = AuthorizationTicketModel(
        ticket_id="tkt_01",
        fingerprint="fp_01",
        history_watermark="wm_01",
        canonical_tx=canonical,
        expires_at=9999999999,
        signature=sig
    )
    assert verify_ticket_integrity(ticket) is True

    # Tamper with amount
    tampered_tx = canonical.model_copy(update={"amount_cents": 500000})
    tampered_ticket = ticket.model_copy(update={"canonical_tx": tampered_tx})
    assert verify_ticket_integrity(tampered_ticket) is False


def test_ticket_replay_prevention(client):
    headers = {"X-Bankism-Mock-User": "alice"}
    prep_res = client.post("/banking/transfers/prepare", json={
        "source_account_id": "ACC-1001-CHK",
        "destination_account_id": "ACC-2002-SAV",
        "amount": 20.00
    }, headers=headers)
    assert prep_res.status_code == 200
    ticket = prep_res.json()["ticket"]

    # First execution succeeds
    res1 = client.post("/banking/transfers/confirm", json={"ticket": ticket}, headers=headers)
    assert res1.status_code == 200

    # Second execution (replay) fails with 409 Conflict
    res2 = client.post("/banking/transfers/confirm", json={"ticket": ticket}, headers=headers)
    assert res2.status_code == 409
    assert "REPLAY" in res2.json()["detail"]


def test_dual_approval_workflow(client):
    # Bob initiates $15,000 transfer (commercial threshold)
    bob_headers = {"X-Bankism-Mock-User": "bob"}
    prep_res = client.post("/banking/transfers/prepare", json={
        "source_account_id": "ACC-3003-BUS",
        "destination_account_id": "ACC-1001-CHK",
        "amount": 15000.00,
        "prompt": "Large equipment wire of $15,000"
    }, headers=bob_headers)
    assert prep_res.status_code == 200
    prep_data = prep_res.json()
    assert prep_data["status"] == "PENDING_DUAL_APPROVAL"
    req_id = prep_data["dual_approval_request"]["request_id"]

    # Bob attempts to self-approve -> Forbidden (403)
    self_appr_res = client.post("/banking/transfers/approve", json={
        "request_id": req_id,
        "approved": True
    }, headers=bob_headers)
    assert self_appr_res.status_code == 403
    assert "SELF_APPROVAL_PROHIBITED" in self_appr_res.json()["detail"]

    # Charlie (Risk Approver) approves -> Success (200) with signed ticket
    charlie_headers = {"X-Bankism-Mock-User": "charlie"}
    charlie_res = client.post("/banking/transfers/approve", json={
        "request_id": req_id,
        "approved": True,
        "reason": "Reviewed invoice"
    }, headers=charlie_headers)
    assert charlie_res.status_code == 200
    ticket = charlie_res.json()["ticket"]
    assert ticket is not None

    # Bob executes using approved ticket
    conf_res = client.post("/banking/transfers/confirm", json={"ticket": ticket}, headers=bob_headers)
    assert conf_res.status_code == 200
    assert conf_res.json()["status"] == "COMPLETED"
