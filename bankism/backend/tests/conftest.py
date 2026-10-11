"""
Pytest Fixtures for Isolated Database and Test Client
"""
import os
import tempfile
import pytest
import sqlite3
from fastapi.testclient import TestClient

from app.main import app
from app.config import settings
from app.banking.database import init_db, get_db_connection
from app.api.routes import get_db


@pytest.fixture
def test_db_path():
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "test_bankism_isolated.db")
    init_db(db_path)
    yield db_path
    if os.path.exists(db_path):
        os.remove(db_path)


@pytest.fixture
def db_conn(test_db_path):
    conn = get_db_connection(test_db_path)
    yield conn
    conn.close()


@pytest.fixture
def client(test_db_path):
    def override_get_db():
        conn = get_db_connection(test_db_path)
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()
