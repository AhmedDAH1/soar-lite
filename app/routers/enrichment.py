from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from typing import List

from app.database import get_db
from app.schemas.ioc import IOCResponse
from app.services.enrichment_service import EnrichmentService
from app.models import IOC

router = APIRouter(
    prefix="/api/enrichment",
    tags=["enrichment"]
)


@router.post("/incident/{incident_id}", response_model=List[IOCResponse])
async def enrich_incident(
    incident_id: int,
    db: Session = Depends(get_db)
):
    """
    Enrich all IOCs for an incident with threat intelligence data.
    
    Queries VirusTotal, AbuseIPDB, and geolocation APIs for each IOC.
    Updates the is_malicious flag and stores enrichment data.
    
    **This can take 5-10 seconds depending on number of IOCs.**
    """
    # Get IOCs for incident
    iocs = db.query(IOC).filter(IOC.incident_id == incident_id).all()
    
    if not iocs:
        raise HTTPException(status_code=404, detail="No IOCs found for this incident")
    
    # Enrich all IOCs concurrently
    enriched_iocs = await EnrichmentService.enrich_incident_iocs(db, incident_id)
    
    return enriched_iocs


@router.post("/ioc/{ioc_id}", response_model=IOCResponse)
async def enrich_single_ioc(
    ioc_id: int,
    db: Session = Depends(get_db)
):
    """
    Enrich a single IOC with threat intelligence data.
    
    Useful for re-enriching specific IOCs or testing enrichment.
    """
    ioc = db.query(IOC).filter(IOC.id == ioc_id).first()
    
    if not ioc:
        raise HTTPException(status_code=404, detail="IOC not found")
    
    enriched_ioc = await EnrichmentService.enrich_ioc(db, ioc)
    
    return enriched_ioc