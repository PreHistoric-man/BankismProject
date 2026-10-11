"""Pytest fixtures for Bankism backend tests."""

import sys
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

# Ensure app package is importable
backend_dir = Path(__file__).resolve().parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from app.main import app
from app.config import Settings, get_settings


@pytest.fixture
def client() -> TestClient:
    """Fixture providing TestClient for FastAPI app."""
    return TestClient(app)


@pytest.fixture
def test_settings() -> Settings:
    """Fixture providing test configuration."""
    return get_settings()
