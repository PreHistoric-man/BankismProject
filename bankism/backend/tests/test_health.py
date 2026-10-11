"""
System Health Tests
"""
def test_health_endpoint(client):
    res = client.get("/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "healthy"
    assert data["subsystems"]["firewall"] == "active"
    assert data["subsystems"]["database"] == "connected"


def test_root_endpoint(client):
    res = client.get("/")
    assert res.status_code == 200
    data = res.json()
    assert "Bankism" in data["system"]
