from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Incident
from app.schemas.triage import TriageResponse
from app.services import triage_service

router = APIRouter(prefix="/api/triage", tags=["ai triage"])


class Decision(BaseModel):
    decision: str   # accept | reject


@router.get("/status")
def status():
    """Which model AI triage uses, in which mode, or why it is off. Never shows the key."""
    return triage_service.status()


@router.post("/incident/{incident_id}", response_model=TriageResponse, status_code=202)
def triage_incident(incident_id: int, db: Session = Depends(get_db)):
    """Ask the AI to triage (or re-triage) an incident. Runs in the background; poll the incident."""
    if not db.query(Incident).filter(Incident.id == incident_id).first():
        raise HTTPException(status_code=404, detail="Incident not found")
    problem = triage_service.model_settings()["problem"]
    if problem:
        raise HTTPException(status_code=400, detail=problem)
    return triage_service.queue(incident_id)


@router.post("/incident/{incident_id}/decision", response_model=TriageResponse)
def decide(incident_id: int, body: Decision,
           analyst_username: str = Query("analyst", max_length=100),
           db: Session = Depends(get_db)):
    """Accept or reject the AI's latest suggestion. Accepting a false alarm closes the incident."""
    try:
        return triage_service.decide(db, incident_id, body.decision, analyst_username)
    except LookupError as e:
        raise HTTPException(status_code=404, detail=str(e)) from None
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from None
