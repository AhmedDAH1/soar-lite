from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_root_endpoint():
    """Test the root endpoint returns correct app info"""
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["app"] == "SOAR-Lite"
    assert data["status"] == "operational"


def test_health_check():
    """Test the health check endpoint"""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "healthy"}