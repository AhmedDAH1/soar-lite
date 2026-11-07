
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.schemas.alert import AlertCreate, AlertResponse
from app.services.alert_service import create_alert_with_incident

router = APIRouter(
    prefix="/api/alerts",
    tags=["alerts"]
)


@router.post("/", response_model=AlertResponse, status_code=201)
def create_alert(
    alert: AlertCreate,
    db: Session = Depends(get_db)
):
    """
    Ingest a new security alert.

    Automatically creates a linked incident for investigation tracking.

    **Example request:**
```json
    {
      "source": "siem",
      "title": "Multiple failed login attempts detected",
      "description": "5 failed SSH login attempts from IP 192.168.1.100",
      "severity": "medium",
      "raw_data": {
        "src_ip": "192.168.1.100",
        "attempts": 5,
        "protocol": "ssh"
      }
    }
```
    """
    try:
        db_alert = create_alert_with_incident(db, alert)
        return db_alert
    except Exception as e:
        # Don't send internal error details to the client
        raise HTTPException(status_code=500, detail="Failed to create alert") from e
