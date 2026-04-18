from fastapi import APIRouter, Depends, HTTPException, Request, Header
from sqlalchemy.orm import Session
from typing import Optional, Dict, Any

from app.database import get_db
from app.schemas.alert import WebhookAlert, AlertResponse
from app.services.alert_service import create_alert_with_incident
from app.services.webhook_service import WebhookService

router = APIRouter(
    prefix="/api/webhooks",
    tags=["webhooks"]
)


@router.post("/generic", response_model=AlertResponse, status_code=201)
async def receive_generic_webhook(
    request: Request,
    webhook_data: Dict[str, Any],
    x_webhook_signature: Optional[str] = Header(None),
    db: Session = Depends(get_db)
):
    """
    Generic webhook endpoint for any alert source.
    
    Accepts flexible JSON format and auto-maps to internal alert schema.
    
    **Example payloads:**
    
    Minimal:
```json
    {
      "source": "custom_scanner",
      "title": "Vulnerability detected"
    }
```
    
    Full:
```json
    {
      "source": "siem",
      "alert_name": "Brute force attack",
      "description": "5 failed logins from 1.2.3.4",
      "severity": "high",
      "raw_data": {"src_ip": "1.2.3.4", "attempts": 5}
    }
```
    
    **Signature Validation (Optional):**
    Include X-Webhook-Signature header for validation:
    X-Webhook-Signature: <HMAC-SHA256 of request body>
    """
    # Validate signature if provided (optional for development)
    if x_webhook_signature:
        body = await request.body()
        secret = "your_webhook_secret"  # In production, load from settings
        
        if not WebhookService.validate_signature(body.decode(), x_webhook_signature, secret):
            raise HTTPException(status_code=401, detail="Invalid webhook signature")
    
    # Parse generic format
    parsed = WebhookService.parse_generic_alert(webhook_data)
    
    # Convert to WebhookAlert schema
    webhook_alert = WebhookAlert(**parsed)
    
    # Convert to AlertCreate
    alert_create = webhook_alert.to_alert_create()
    
    # Create incident
    db_alert = create_alert_with_incident(db, alert_create)
    
    return db_alert


@router.post("/siem", response_model=AlertResponse, status_code=201)
def receive_siem_webhook(
    webhook_data: Dict[str, Any],
    db: Session = Depends(get_db)
):
    """
    SIEM-specific webhook endpoint (Splunk, QRadar, etc).
    
    **Example Splunk alert:**
```json
    {
      "search_name": "Multiple Failed Logins",
      "result": {
        "src_ip": "192.168.1.100",
        "dest_ip": "10.0.0.5",
        "count": 15
      },
      "severity": "high"
    }
```
    """
    parsed = WebhookService.parse_siem_alert(webhook_data)
    webhook_alert = WebhookAlert(**parsed)
    alert_create = webhook_alert.to_alert_create()
    db_alert = create_alert_with_incident(db, alert_create)
    
    return db_alert


@router.post("/edr", response_model=AlertResponse, status_code=201)
def receive_edr_webhook(
    webhook_data: Dict[str, Any],
    db: Session = Depends(get_db)
):
    """
    EDR-specific webhook endpoint (CrowdStrike, SentinelOne, etc).
    
    **Example CrowdStrike alert:**
```json
    {
      "alert_type": "malware_detected",
      "hostname": "LAPTOP-ABC123",
      "file_hash": "44d88612fea8a8f36de82e1278abb02f",
      "severity": "critical",
      "user": "john.doe"
    }
```
    """
    parsed = WebhookService.parse_edr_alert(webhook_data)
    webhook_alert = WebhookAlert(**parsed)
    alert_create = webhook_alert.to_alert_create()
    db_alert = create_alert_with_incident(db, alert_create)
    
    return db_alert


@router.post("/email", response_model=AlertResponse, status_code=201)
def receive_email_webhook(
    webhook_data: Dict[str, Any],
    db: Session = Depends(get_db)
):
    """
    Email gateway webhook endpoint (Proofpoint, Mimecast, etc).
    
    **Example phishing report:**
```json
    {
      "from": "phisher@evil.com",
      "subject": "URGENT: Verify your account",
      "recipient": "victim@company.com",
      "verdict": "phishing",
      "urls": ["http://evil.com/fake-login"],
      "attachments": ["invoice.zip"]
    }
```
    """
    parsed = WebhookService.parse_email_alert(webhook_data)
    webhook_alert = WebhookAlert(**parsed)
    alert_create = webhook_alert.to_alert_create()
    db_alert = create_alert_with_incident(db, alert_create)
    
    return db_alert