from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Incident
from app.services.report_service import ReportService

router = APIRouter(
    prefix="/api/reports",
    tags=["reports"]
)


@router.get("/incident/{incident_id}/pdf")
def download_pdf_report(
    incident_id: int,
    db: Session = Depends(get_db)
):
    """
    Download incident report as PDF.
    
    Includes:
    - Executive summary
    - Alert details
    - IOC table with enrichment data
    - Full timeline
    """
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    
    # Generate PDF
    pdf_buffer = ReportService.generate_pdf_report(incident)
    
    # Return as downloadable file
    filename = f"incident_{incident_id}_report.pdf"
    
    return StreamingResponse(
        pdf_buffer,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


@router.get("/incident/{incident_id}/docx")
def download_docx_report(
    incident_id: int,
    db: Session = Depends(get_db)
):
    """
    Download incident report as editable DOCX.
    
    Useful for:
    - Adding analyst notes
    - Customizing for specific stakeholders
    - Appending additional evidence
    """
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    
    # Generate DOCX
    docx_buffer = ReportService.generate_docx_report(incident)
    
    # Return as downloadable file
    filename = f"incident_{incident_id}_report.docx"
    
    return StreamingResponse(
        docx_buffer,
        media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )