from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.config import get_settings
from app.database import get_db
from app.models import Incident
from app.services import analysis_service, soc_context, triage_service

router = APIRouter(prefix="/api/analyze", tags=["analyze"])

SAMPLES_DIR = Path("samples/demo")


class UploadedFile(BaseModel):
    name: str
    content: str


class AnalyzeRequest(BaseModel):
    files: list[UploadedFile]
    triage: bool = True      # False: open incidents without asking the AI (e.g. automated checks)


@router.post("/")
def analyze(request: AnalyzeRequest, db: Session = Depends(get_db)) -> dict[str, Any]:
    """
    Analyse logs and emails: each detection becomes an incident, then goes to AI triage.

    Logs go to Log Threat Detector, emails to Email Threat Analyzer (see
    LOG_ANALYZER_URL and EMAIL_ANALYZER_URL).
    """
    files = [f.model_dump() for f in request.files]
    problem = analysis_service.validate(files)
    if problem:
        raise HTTPException(status_code=400, detail=problem)
    try:
        result = analysis_service.analyze_files(db, files)
    except analysis_service.AnalyzerUnavailableError as e:
        raise HTTPException(status_code=502, detail=str(e)) from None

    # Files someone chose to analyse are always triaged when a model is set;
    # AUTO_TRIAGE only governs incidents that arrive by webhook.
    if request.triage:
        for incident_id in result["incident_ids"]:
            triage_service.queue(incident_id)
    incidents = db.query(Incident).filter(Incident.id.in_(result["incident_ids"])).all() if result["incident_ids"] else []
    result["incidents"] = [{"id": i.id, "title": i.title, "severity": i.severity.value} for i in incidents]
    return result


@router.get("/status")
def status() -> dict[str, Any]:
    """Whether the detection tools and the AI model are ready, for the dashboard."""
    records = soc_context.load()
    context = {"file": get_settings().SOC_CONTEXT_FILE, "hosts": len(records.get("by_ip") or {}),
               "domains": len(records.get("by_domain") or {})}
    return {**analysis_service.analyzers_status(), "ai": triage_service.status(), "context": context}


@router.get("/samples")
def samples() -> list[dict[str, str]]:
    """The bundled demo files: logs and emails with real attacks, false alarms and a prompt injection."""
    if not SAMPLES_DIR.is_dir():
        return []
    return [{"name": p.name, "content": p.read_text(encoding="utf-8")}
            for p in sorted(SAMPLES_DIR.iterdir()) if p.is_file() and not p.name.startswith(".")]
