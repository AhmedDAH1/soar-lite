from fastapi.testclient import TestClient

from app.main import app
from app.services.ioc_extractor import IOCExtractor
from app.services.playbook_engine import PlaybookEngine

client = TestClient(app)


# ========== IOC Extraction Edge Cases ==========

def test_extract_no_iocs():
    """Test extraction from text with no IOCs"""
    text = "This is just normal text with no indicators"
    iocs = IOCExtractor.extract_from_text(text)
    assert len(iocs) == 0


def test_extract_multiple_same_ioc():
    """Test that duplicate IOCs are not extracted twice"""
    text = "IP 8.8.8.8 appeared, then 8.8.8.8 again, and 8.8.8.8 once more"
    iocs = IOCExtractor.extract_from_text(text)

    ip_iocs = [ioc for ioc in iocs if ioc["type"].value == "ip"]
    assert len(ip_iocs) == 1  # Only extracted once despite 3 occurrences


def test_extract_invalid_ip():
    """Test that invalid IPs are filtered out"""
    text = "Invalid IPs: 999.999.999.999 and 256.1.1.1"
    iocs = IOCExtractor.extract_from_text(text)

    ip_iocs = [ioc for ioc in iocs if ioc["type"].value == "ip"]
    assert len(ip_iocs) == 0  # Both invalid, should be filtered


def test_extract_from_none():
    """Test extraction handles None input gracefully"""
    iocs = IOCExtractor.extract_from_text(None)
    assert iocs == []


def test_extract_from_empty_string():
    """Test extraction handles empty string"""
    iocs = IOCExtractor.extract_from_text("")
    assert iocs == []


# ========== Playbook Edge Cases ==========

def test_playbook_condition_missing_field():
    """Test playbook handles missing fields gracefully"""
    condition = {
        "field": "ioc.nonexistent_field",
        "operator": "equals",
        "value": "test"
    }
    context = {"ioc": {"type": "ip"}}

    result = PlaybookEngine.evaluate_condition(condition, context)
    assert result is False  # Missing field should fail condition


def test_playbook_invalid_operator():
    """Test playbook handles unknown operators"""
    condition = {
        "field": "ioc.type",
        "operator": "unknown_operator",
        "value": "ip"
    }
    context = {"ioc": {"type": "ip"}}

    result = PlaybookEngine.evaluate_condition(condition, context)
    assert result is False  # Unknown operator should fail safely


def test_playbook_nested_field_none():
    """Test nested field access when intermediate value is None"""
    context = {
        "enrichment_data": None
    }

    value = PlaybookEngine._get_nested_value(context, "enrichment_data.virustotal.malicious")
    assert value is None


# ========== Alert Creation Edge Cases ==========

def test_create_alert_minimal_data():
    """Test alert creation with only required fields"""
    payload = {
        "source": "test",
        "title": "Minimal Alert"
    }

    response = client.post("/api/alerts/", json=payload)
    assert response.status_code == 201

    data = response.json()
    assert data["source"] == "test"
    assert data["title"] == "Minimal Alert"
    assert data["description"] is None  # Optional field


def test_create_alert_very_long_title():
    """Test alert with title at max length"""
    long_title = "A" * 255  # Max length
    payload = {
        "source": "test",
        "title": long_title
    }

    response = client.post("/api/alerts/", json=payload)
    assert response.status_code == 201


def test_create_alert_empty_title():
    """Test alert with empty title is rejected"""
    payload = {
        "source": "test",
        "title": ""
    }

    response = client.post("/api/alerts/", json=payload)
    assert response.status_code == 422  # Validation error




# ========== Incident Management Edge Cases ==========

def test_update_nonexistent_incident():
    """Test updating incident that doesn't exist"""
    response = client.patch(
        "/api/incidents/999999",
        json={"status": "investigating"}
    )
    assert response.status_code == 404


def test_update_incident_no_changes():
    """Test updating incident with no actual changes"""
    # Create incident
    alert_response = client.post("/api/alerts/", json={
        "source": "test",
        "title": "No change test"
    })
    incident_id = alert_response.json()["incident_id"]

    # Update with same values
    response = client.patch(
        f"/api/incidents/{incident_id}",
        json={"status": "new"}  # Already NEW
    )
    assert response.status_code == 200


def test_search_incidents_no_results():
    """Test incident search with criteria that matches nothing"""
    response = client.get("/api/incidents/?search=NONEXISTENT_SEARCH_TERM_12345")
    assert response.status_code == 200
    assert len(response.json()) == 0


def test_filter_incidents_invalid_severity():
    """Test filtering with invalid severity"""
    response = client.get("/api/incidents/?severity=invalid")
    assert response.status_code == 200  # Should return all (ignore bad filter)


# ========== Webhook Edge Cases ==========

def test_webhook_minimal_payload():
    """Test webhook with absolute minimum data"""
    payload = {
        "source": "minimal"
    }

    response = client.post("/api/webhooks/generic", json=payload)
    assert response.status_code == 201


def test_webhook_empty_payload():
    """Test webhook with empty JSON"""
    payload = {}

    response = client.post("/api/webhooks/generic", json=payload)
    # Should either create with defaults or reject
    assert response.status_code in [201, 422]


def test_webhook_unknown_fields():
    """Test webhook ignores unknown fields gracefully"""
    payload = {
        "source": "test",
        "title": "Test",
        "unknown_field_xyz": "should be ignored",
        "another_unknown": 12345
    }

    response = client.post("/api/webhooks/generic", json=payload)
    assert response.status_code == 201


# ========== Report Generation Edge Cases ==========

def test_generate_pdf_empty_incident():
    """Test PDF generation for incident with no alerts/IOCs"""
    # Create minimal incident
    alert_response = client.post("/api/alerts/", json={
        "source": "test",
        "title": "Empty incident"
    })
    incident_id = alert_response.json()["incident_id"]

    # Delete all IOCs to make it truly empty (if needed)

    response = client.get(f"/api/reports/incident/{incident_id}/pdf")
    assert response.status_code == 200
    assert len(response.content) > 0  # Should still generate PDF


def test_generate_report_nonexistent_incident():
    """Test report generation for non-existent incident"""
    response = client.get("/api/reports/incident/999999/pdf")
    assert response.status_code == 404
