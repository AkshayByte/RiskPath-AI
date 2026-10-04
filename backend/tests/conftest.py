"""
Pytest configuration and session-wide fixtures for RiskPath AI test suites.
Ensures database schema and seed data are initialized before any tests run.
"""
import pytest
from backend.app.core.database import engine
from backend.app.models.database import Base
from backend.data.seeds.seed_data import create_seed_data


@pytest.fixture(scope="session", autouse=True)
def setup_test_database():
    """
    Session-wide fixture that runs automatically before any test:
    - Creates all database tables on the active database engine
    - Idempotently populates seed scenario data
    """
    Base.metadata.create_all(bind=engine)
    try:
        create_seed_data()
    except Exception as e:
        print(f"[conftest] Seed data initialization notice: {e}")
    yield
