from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_create_alert_success():
    """Test creating a valid alert"""
    payload = {
        "source": "edr",
        "title": "Malware detected on endpoint",
        "description": "Ransomware signature detected",
        "severity": "critical",
        "raw_data": {
            "host": "DESKTOP-123",
            "malware_family": "ransomware"
        }
    }
    
    response = client.post("/api/alerts/", json=payload)
    
    assert response.status_code == 201
    data = response.json()
    
    # Verify alert fields
    assert data["source"] == "edr"
    assert data["title"] == "Malware detected on endpoint"
    assert data["id"] is not None
    assert data["incident_id"] is not None
    assert data["raw_data"]["malware_family"] == "ransomware"


def test_create_alert_missing_required_fields():
    """Test that missing required fields returns 422"""
    payload = {
        "source": "siem"
        # Missing 'title' field
    }
    
    response = client.post("/api/alerts/", json=payload)
    assert response.status_code == 422  # Validation error


def test_create_alert_creates_incident():
    """Test that creating an alert also creates an incident"""
    payload = {
        "source": "email_gateway",
        "title": "Phishing email detected",
        "severity": "medium"
    }
    
    response = client.post("/api/alerts/", json=payload)
    assert response.status_code == 201
    
    data = response.json()
    assert data["incident_id"] > 0  # Incident was created