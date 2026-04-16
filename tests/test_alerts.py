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

def test_create_alert_extracts_iocs():
    """Test that creating an alert automatically extracts IOCs"""
    payload = {
        "source": "siem",
        "title": "C2 communication detected",
        "description": "Host contacted 185.220.101.50 (evil.com)",
        "severity": "high"
    }
    
    response = client.post("/api/alerts/", json=payload)
    assert response.status_code == 201
    
    incident_id = response.json()["incident_id"]
    
    # Check IOCs were extracted
    iocs_response = client.get(f"/api/iocs/incident/{incident_id}")
    assert iocs_response.status_code == 200
    
    iocs = iocs_response.json()
    assert len(iocs) > 0  # At least IP and domain extracted
    
    # Verify IP was extracted
    ip_values = [ioc["value"] for ioc in iocs if ioc["type"] == "ip"]
    assert "185.220.101.50" in ip_values