"""
Banking Ledger & Accounts Tests
"""
def test_list_accounts_authorized(client):
    headers = {"X-Bankism-Mock-User": "alice"}
    res = client.get("/banking/accounts", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert len(data) == 2
    acc_ids = [a["account_id"] for a in data]
    assert "ACC-1001-CHK" in acc_ids
    assert "ACC-2002-SAV" in acc_ids


def test_list_accounts_requires_auth(client):
    res = client.get("/banking/accounts")
    assert res.status_code == 401


def test_prepare_transfer_insufficient_funds(client):
    headers = {"X-Bankism-Mock-User": "alice"}
    payload = {
        "source_account_id": "ACC-1001-CHK",
        "destination_account_id": "ACC-2002-SAV",
        "amount": 9999999.00,  # Far exceeds balance
    }
    res = client.post("/banking/transfers/prepare", json=payload, headers=headers)
    assert res.status_code == 400
    assert "INSUFFICIENT_FUNDS" in res.json()["detail"]


def test_prepare_transfer_cross_account_denied(client):
    # Bob trying to spend Alice's checking account
    headers = {"X-Bankism-Mock-User": "bob"}
    payload = {
        "source_account_id": "ACC-1001-CHK",
        "destination_account_id": "ACC-3003-BUS",
        "amount": 50.00,
    }
    res = client.post("/banking/transfers/prepare", json=payload, headers=headers)
    assert res.status_code == 403
    assert "ACCOUNT_ACCESS_DENIED" in res.json()["detail"]


def test_successful_transfer_flow(client):
    headers = {"X-Bankism-Mock-User": "alice"}
    prep_res = client.post("/banking/transfers/prepare", json={
        "source_account_id": "ACC-1001-CHK",
        "destination_account_id": "ACC-2002-SAV",
        "amount": 50.00,
        "prompt": "Transfer $50 from checking to savings"
    }, headers=headers)
    assert prep_res.status_code == 200
    prep_data = prep_res.json()
    assert prep_data["status"] == "AUTHORIZED"
    ticket = prep_data["ticket"]
    assert ticket is not None

    # Confirm & execute transfer
    conf_res = client.post("/banking/transfers/confirm", json={"ticket": ticket}, headers=headers)
    assert conf_res.status_code == 200
    conf_data = conf_res.json()
    assert conf_data["status"] == "COMPLETED"
    assert conf_data["receipt"]["amount_cents"] == 5000
