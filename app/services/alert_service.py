from sqlalchemy.orm import Session
from app.models import Alert, Incident, SeverityEnum
from app.schemas.alert import AlertCreate


def create_alert_with_incident(db: Session, alert: AlertCreate) -> Alert:
    """
    Creates an alert and automatically creates a linked incident.
    
    This is the core alert ingestion logic:
    1. Create a new incident for this alert
    2. Link the alert to the incident
    3. Return the created alert
    
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
        # Status defaults to NEW from model definition
    )
    db.add(incident)
    db.flush()  # Get incident.id without committing
    
    # Create alert linked to incident
    db_alert = Alert(
        incident_id=incident.id,
        source=alert.source,
        title=alert.title,
        description=alert.description,
        raw_data=alert.raw_data,
    )
    db.add(db_alert)
    db.commit()
    db.refresh(db_alert)
    
    return db_alert