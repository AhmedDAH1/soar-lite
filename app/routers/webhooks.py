import time
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.config import get_settings
from app.database import get_db
from app.schemas.alert import AlertResponse, WebhookAlert
from app.services.alert_service import create_alert_with_incident
from app.services.webhook_service import SIGNATURE_HEADER, TIMESTAMP_HEADER, WebhookService


async def require_signature(request: Request):
    """
    Refuse any webhook request that isn't signed with WEBHOOK_SECRET.

    Without this, anyone who can reach the server could create incidents,
    or flood the queue with fake alerts to hide a real one.
    """
    settings = get_settings()
    if not settings.WEBHOOK_SECRET:
        raise HTTPException(status_code=503, detail="Webhooks are disabled: WEBHOOK_SECRET is not set")
    problem = WebhookService.check_signature(
        body=await request.body(),
        secret=settings.WEBHOOK_SECRET,
        timestamp=request.headers.get(TIMESTAMP_HEADER),
        signature=request.headers.get(SIGNATURE_HEADER),
        now=time.time(),
        max_age=settings.WEBHOOK_MAX_AGE,
    )
    if problem:
        raise HTTPException(status_code=401, detail=problem)


router = APIRouter(
    prefix="/api/webhooks",
    tags=["webhooks"],
    dependencies=[Depends(require_signature)],
)


@router.post("/generic", response_model=AlertResponse, status_code=201)
def receive_generic_webhook(
    webhook_data: dict[str, Any],
    db: Session = Depends(get_db)
):
    """
    Generic webhook endpoint for any alert source.

    Accepts flexible JSON format and auto-maps to internal alert schema.
    Requests must be signed (see the README, "Sending alerts").

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
    """
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
    webhook_data: dict[str, Any],
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
    webhook_data: dict[str, Any],
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
    webhook_data: dict[str, Any],
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
