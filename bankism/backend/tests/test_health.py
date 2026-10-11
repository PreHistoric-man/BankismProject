"""Tests for the /health endpoint."""

import sys
from pathlib import Path

backend_dir = Path(__file__).resolve().parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from fastapi.testclient import TestClient


def test_health_check_success(client: TestClient):
    """Test that GET /health returns 200 and healthy subsystems."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "app_name" in data
    assert "version" in data
    assert "subsystems" in data
    assert data["subsystems"]["firewall_inspector"] == "ready"
    assert data["subsystems"]["threat_detector"] == "ready"
    assert data["subsystems"]["policy_engine"] == "ready"
    assert data["subsystems"]["banking_guardrails"] == "enforced"


def test_api_prefixed_health_check(client: TestClient):
    """Test that GET /api/health also succeeds."""
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
