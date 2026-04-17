from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, JSON
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from app.database import Base


class Action(Base):
    """
    Action/Timeline model representing automated or manual actions taken on an incident.
    
    This serves as both:
    - Audit log (who did what, when)
    - Timeline (chronological view of incident response)
    """
    __tablename__ = "actions"
    
    id = Column(Integer, primary_key=True, index=True)
    
    # Link to parent incident
    incident_id = Column(Integer, ForeignKey("incidents.id"), nullable=False)
    
    # Action metadata
    action_type = Column(String(100), nullable=False)  # e.g., "playbook_executed", "severity_updated"
    description = Column(Text, nullable=False)
    
    # Playbook info (if triggered by playbook)
    playbook_name = Column(String(255), nullable=True)
    
    # Additional context (renamed from 'metadata' to avoid SQLAlchemy reserved word)
    action_metadata = Column(JSON, nullable=True)  # ← CHANGED: metadata → action_metadata
    
    # Attribution
    performed_by = Column(String(100), default="system")  # "system" or analyst username
    
    # Timestamp
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationship
    incident = relationship("Incident", back_populates="actions")