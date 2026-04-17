from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List, Optional

from app.database import get_db
from app.schemas.incident import IncidentResponse, IncidentDetailResponse, IncidentUpdate
from app.services.incident_service import IncidentService
from app.models import Incident

router = APIRouter(
    prefix="/api/incidents",
    tags=["incidents"]
)


@router.get("/", response_model=List[IncidentResponse])
def list_incidents(
    severity: Optional[str] = Query(None, description="Filter by severity (low/medium/high/critical)"),
    status: Optional[str] = Query(None, description="Filter by status (new/investigating/contained/resolved)"),
    search: Optional[str] = Query(None, description="Search in title/description"),
    ioc_value: Optional[str] = Query(None, description="Find incidents with this IOC"),
    days: Optional[int] = Query(None, description="Only incidents from last N days"),
    limit: int = Query(100, le=500, description="Max results (max 500)"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
    db: Session = Depends(get_db)
):
    """
    List incidents with optional filtering and search.
    
    **Examples:**
    - `/api/incidents?severity=critical` - All critical incidents
    - `/api/incidents?status=new&days=7` - New incidents from last week
    - `/api/incidents?search=phishing` - Search for "phishing" in title/description
    - `/api/incidents?ioc_value=evil.com` - Find incidents with this IOC
    """
    incidents = IncidentService.search_incidents(
        db=db,
        severity=severity,
        status=status,
        search=search,
        ioc_value=ioc_value,
        days=days,
        limit=limit,
        offset=offset
    )
    
    return incidents


@router.get("/statistics")
def get_statistics(db: Session = Depends(get_db)):
    """
    Get incident statistics for dashboard.
    
    Returns counts by severity, status, and key metrics.
    """
    stats = IncidentService.get_statistics(db)
    return stats


@router.get("/{incident_id}", response_model=IncidentDetailResponse)
def get_incident(
    incident_id: int,
    db: Session = Depends(get_db)
):
    """
    Get full incident details including alerts, IOCs, and timeline.
    """
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    
    return incident


@router.patch("/{incident_id}", response_model=IncidentResponse)
def update_incident(
    incident_id: int,
    updates: IncidentUpdate,
    analyst_username: str = Query("analyst", description="Username of analyst making update"),
    db: Session = Depends(get_db)
):
    """
    Update incident fields.
    
    **Examples:**
```json
    {
      "status": "investigating",
      "severity": "high",
      "description": "Updated description with analyst notes"
    }
```
    
    All fields are optional - only send fields you want to update.
    Status transitions are validated (e.g., can't go from NEW to RESOLVED).
    """
    incident = IncidentService.update_incident(
        db=db,
        incident_id=incident_id,
        updates=updates,
        analyst_username=analyst_username
    )
    
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    
    return incident