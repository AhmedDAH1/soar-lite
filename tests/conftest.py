import pytest

from app.database import Base, engine


@pytest.fixture(scope="session", autouse=True)
def setup_database():
    """Create all database tables before running tests"""
    Base.metadata.create_all(bind=engine)
    yield
    # Cleanup after all tests
    Base.metadata.drop_all(bind=engine)
