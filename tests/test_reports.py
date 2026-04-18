from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_generate_pdf_report():
    """Test PDF report generation"""
    # Create incident first
    alert_response = client.post("/api/alerts/", json={
        "source": "test",
        "title": "Test incident for PDF report",
        "description": "Testing PDF generation with IOCs: 8.8.8.8",
        "severity": "high"
    })
    incident_id = alert_response.json()["incident_id"]
    
    # Generate PDF report
    response = client.get(f"/api/reports/incident/{incident_id}/pdf")
    
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/pdf"
    assert "attachment" in response.headers["content-disposition"]
    assert len(response.content) > 1000  # PDF should have substantial content


def test_generate_docx_report():
    """Test DOCX report generation"""
    # Create incident
    alert_response = client.post("/api/alerts/", json={
        "source": "test",
        "title": "Test incident for DOCX report",
        "severity": "medium"
    })
    incident_id = alert_response.json()["incident_id"]
    
    # Generate DOCX report
    response = client.get(f"/api/reports/incident/{incident_id}/docx")
    
    assert response.status_code == 200
    assert "wordprocessingml" in response.headers["content-type"]
    assert "attachment" in response.headers["content-disposition"]
    assert len(response.content) > 1000


def test_report_nonexistent_incident():
    """Test report generation for non-existent incident"""
    response = client.get("/api/reports/incident/99999/pdf")
    assert response.status_code == 404