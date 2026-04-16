from sqlalchemy.orm import Session
from app.models import Alert, Incident, IOC, SeverityEnum
from app.schemas.alert import AlertCreate
from app.services.ioc_extractor import IOCExtractor


def create_alert_with_incident(db: Session, alert: AlertCreate) -> Alert:
    """
    Creates an alert and automatically creates a linked incident.
    Also extracts IOCs from alert data.
    
    Workflow:
    1. Create incident
    2. Create alert
    3. Extract IOCs from alert text
    4. Store IOCs linked to incident
    
    Args:
        db: Database session
        alert: Alert data from API request
        
    Returns:
        Created Alert object with incident relationship loaded
    """
    
    # Create incident from alert data
    incident = Incident(
        title=f"[{alert.source.upper()}] {alert.title}",
        description=alert.description,
        severity=SeverityEnum[alert.severity.upper()] if alert.severity else SeverityEnum.MEDIUM,
    )
    db.add(incident)
    db.flush()  # Get incident.id
    
    # Create alert linked to incident
    db_alert = Alert(
        incident_id=incident.id,
        source=alert.source,
        title=alert.title,
        description=alert.description,
        raw_data=alert.raw_data,
    )
    db.add(db_alert)
    db.flush()  # Save alert before extracting IOCs
    
    # Extract IOCs from alert data
    alert_dict = {
        "title": alert.title,
        "description": alert.description,
        "raw_data": alert.raw_data
    }
    extracted_iocs = IOCExtractor.extract_from_alert_data(alert_dict)
    
    # Store extracted IOCs
    for ioc_data in extracted_iocs:
        db_ioc = IOC(
            incident_id=incident.id,
            type=ioc_data["type"],
            value=ioc_data["value"],
            extracted_from=ioc_data["extracted_from"]
        )
        db.add(db_ioc)
    
    db.commit()
    db.refresh(db_alert)
    
    return db_alert