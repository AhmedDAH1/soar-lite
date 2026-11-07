
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import IOC
from app.schemas.ioc import IOCResponse

router = APIRouter(
    prefix="/api/iocs",
    tags=["iocs"]
)


@router.get("/incident/{incident_id}", response_model=list[IOCResponse])
def get_incident_iocs(
    incident_id: int,
    db: Session = Depends(get_db)
):
    """
    Get all IOCs associated with an incident.

    This is useful for:
    - Reviewing what indicators were extracted from alerts
    - Pivoting (searching for these IOCs in other incidents)
    - Feeding IOCs to enrichment APIs
    """
    iocs = db.query(IOC).filter(IOC.incident_id == incident_id).all()

    if not iocs:
        return []  # Return empty list instead of 404

    return iocs
