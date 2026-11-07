import os

# Settings are read once, when the app is first imported, so test settings
# must be in the environment before that.
os.environ.setdefault("WEBHOOK_SECRET", "test-webhook-secret")
os.environ.pop("DEMO_MODE", None)
os.environ.pop("SEED_DEMO", None)

import pytest

from app.database import Base, engine


@pytest.fixture(scope="session", autouse=True)
def setup_database():
    """Create all database tables before running tests"""
    Base.metadata.create_all(bind=engine)
    yield
    # Cleanup after all tests
    Base.metadata.drop_all(bind=engine)
