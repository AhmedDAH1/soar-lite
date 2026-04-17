from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_list_incidents():
    """Test listing all incidents"""
    response = client.get("/api/incidents/")
    assert response.status_code == 200
    assert isinstance(response.json(), list)


def test_filter_incidents_by_severity():
    """Test filtering by severity"""
    # Create a critical incident first
    alert = {
        "source": "test",
        "title": "Test critical alert",
        "severity": "critical"
    }
    client.post("/api/alerts/", json=alert)
    
    # Filter for critical
    response = client.get("/api/incidents/?severity=critical")
    assert response.status_code == 200
    incidents = response.json()
    
    # All returned incidents should be critical
    for incident in incidents:
        assert incident["severity"] == "critical"


def test_get_incident_detail():
    """Test getting full incident details"""
    # Create incident
    alert_response = client.post("/api/alerts/", json={
        "source": "test",
        "title": "Test detail incident",
        "description": "With IOCs: 8.8.8.8",
        "severity": "medium"
    })
    incident_id = alert_response.json()["incident_id"]
    
    # Get details
    response = client.get(f"/api/incidents/{incident_id}")
    assert response.status_code == 200
    
    data = response.json()
    assert data["id"] == incident_id
    assert "alerts" in data
    assert "iocs" in data
    assert "actions" in data
    assert len(data["alerts"]) > 0


def test_update_incident_status():
    """Test updating incident status"""
    # Create incident
    alert_response = client.post("/api/alerts/", json={
        "source": "test",
        "title": "Test status update",
        "severity": "low"
    })
    incident_id = alert_response.json()["incident_id"]
    
    # Update to investigating
    response = client.patch(
        f"/api/incidents/{incident_id}",
        json={"status": "investigating"},
        params={"analyst_username": "test_analyst"}
    )
    assert response.status_code == 200
    assert response.json()["status"] == "investigating"


def test_invalid_status_transition():
    """Test that invalid status transitions are rejected"""
    # Create incident (status: NEW)
    alert_response = client.post("/api/alerts/", json={
        "source": "test",
        "title": "Test invalid transition",
        "severity": "low"
    })
    incident_id = alert_response.json()["incident_id"]
    
    # Try to jump to RESOLVED (invalid)
    response = client.patch(
        f"/api/incidents/{incident_id}",
        json={"status": "resolved"}
    )
    
    # Request succeeds but status doesn't change
    assert response.status_code == 200
    assert response.json()["status"] == "new"  # Still NEW


def test_search_incidents():
    """Test text search in incidents"""
    # Create searchable incident
    client.post("/api/alerts/", json={
        "source": "test",
        "title": "Unique_Search_Term_12345",
        "severity": "low"
    })
    
    # Search for it
    response = client.get("/api/incidents/?search=Unique_Search_Term_12345")
    assert response.status_code == 200
    incidents = response.json()
    
    assert len(incidents) > 0
    assert "Unique_Search_Term_12345" in incidents[0]["title"]


def test_get_statistics():
    """Test statistics endpoint"""
    response = client.get("/api/incidents/statistics")
    assert response.status_code == 200
    
    stats = response.json()
    assert "total_incidents" in stats
    assert "by_status" in stats
    assert "by_severity" in stats
    assert "unresolved" in stats