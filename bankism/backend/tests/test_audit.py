"""
Tamper-Evident Hash Chain Audit Tests
"""
from app.audit.tamper_evident import append_audit_event, verify_audit_chain


def test_audit_chain_verification_unbroken(db_conn):
    # Append events
    append_audit_event(db_conn, "ev_01", "LOGIN", "USR-4401-ALICE", {"ip": "127.0.0.1"})
    append_audit_event(db_conn, "ev_02", "INSPECT", "USR-4401-ALICE", {"prompt": "check balance"})
    result = verify_audit_chain(db_conn)
    assert result["valid"] is True
    assert result["total_events"] >= 2


def test_audit_chain_detects_payload_tampering(db_conn):
    ev_id = "ev_tamper_test"
    append_audit_event(db_conn, ev_id, "TRANSFER", "USR-4401-ALICE", {"amount_cents": 1000})

    # Tamper with the stored payload in SQLite
    db_conn.execute(
        "UPDATE tamper_evident_audit_logs SET payload_json = ? WHERE event_id = ?;",
        ('{"amount_cents": 999999}', ev_id)
    )

    result = verify_audit_chain(db_conn)
    assert result["valid"] is False
    assert result["broken_at_index"] is not None
    assert "Tampered event content" in result["details"]


def test_audit_verify_endpoint(client):
    res = client.get("/banking/audit/verify")
    assert res.status_code == 200
    assert "valid" in res.json()
