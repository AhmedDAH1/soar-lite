from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_root_endpoint():
    """Test the root endpoint serves dashboard HTML"""
    response = client.get("/")
    assert response.status_code == 200
    # Root now serves HTML dashboard, not JSON
    assert response.headers["content-type"].startswith("text/html")
    assert len(response.content) > 0  # Should return HTML content

def test_health_check():
    """Test the health check endpoint"""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "healthy"}