from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_root_endpoint():
    """Test the root endpoint serves dashboard HTML"""
    response = client.get("/")
    assert response.status_code == 200
    # Root now serves HTML dashboard, not JSON
    assert "text/html" in response.headers.get("content-type", "")


def test_health_check():
    """Test the health check endpoint"""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "version" in data
    assert "database" in data
