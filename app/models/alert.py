from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, JSON
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from app.database import Base


class Alert(Base):
    """
    Alert model representing a security detection event from external sources.
    
    Alerts are immutable records of detections from SIEMs, EDRs, email gateways, etc.
    Each alert is linked to an incident for investigation tracking.
    """
    __tablename__ = "alerts"
    
    id = Column(Integer, primary_key=True, index=True)
    
    # Link to parent incident
    incident_id = Column(Integer, ForeignKey("incidents.id"), nullable=False)
    
    # Alert metadata
    source = Column(String(100), nullable=False)  # e.g., "siem", "edr", "email_gateway"
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    
    # Raw alert data from source (preserves original format)
    raw_data = Column(JSON, nullable=True)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationship to incident
    incident = relationship("Incident", back_populates="alerts")