from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List, Dict

from app.database import get_db
from app.services.playbook_engine import PlaybookEngine

from app.schemas.action import ActionResponse
from app.models import Action

router = APIRouter(
    prefix="/api/playbooks",
    tags=["playbooks"]
)


@router.get("/", response_model=List[Dict])
def list_playbooks():
    """
    List all enabled playbooks.
    
    Returns playbook metadata (name, description, conditions, actions).
    """
    playbooks = PlaybookEngine.load_playbooks()
    
    # Return simplified view
    return [
        {
            "name": p.get("name"),
            "description": p.get("description"),
            "version": p.get("version"),
            "enabled": p.get("enabled", True),
            "conditions": len(p.get("conditions", [])),
            "actions": len(p.get("actions", []))
        }
        for p in playbooks
    ]


@router.post("/execute/{incident_id}", response_model=Dict)
def execute_playbooks(
    incident_id: int,
    db: Session = Depends(get_db)
):
    """
    Manually execute all playbooks against an incident.
    
    Typically called after enrichment completes, but can be triggered manually
    by analysts to re-run automation rules.
    """
    results = PlaybookEngine.run_playbooks_for_incident(incident_id, db)
    
    if "error" in results:
        raise HTTPException(status_code=404, detail=results["error"])
    
    return results

@router.get("/timeline/{incident_id}", response_model=List[ActionResponse])
def get_incident_timeline(
    incident_id: int,
    db: Session = Depends(get_db)
):
    """
    Get chronological timeline of all actions for an incident.
    
    Shows both automated (playbook) and manual actions.
    """
    actions = db.query(Action).filter(
        Action.incident_id == incident_id
    ).order_by(Action.created_at.asc()).all()
    
    return actions