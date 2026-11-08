from sqlalchemy import JSON, Boolean, Column, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from app.database import Base


class TriageResult(Base):
    """
    An AI model's suggested verdict for an incident (see app/services/triage_service.py).

    The model only suggests: nothing here changes the incident until an analyst
    accepts it. Every field the model wrote is untrusted text, like an alert's.
    """
    __tablename__ = "triage_results"

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"), nullable=False, index=True)

    # pending → done | failed (| disabled, if the model was removed while it waited)
    status = Column(String(20), nullable=False, default="pending")
    mode = Column(String(20), nullable=False, default="strict")
    model = Column(String(200), nullable=True)

    verdict = Column(String(30), nullable=True)          # true_positive | false_positive | needs_investigation
    severity = Column(String(20), nullable=True)
    confidence = Column(Float, nullable=True)
    reasoning = Column(Text, nullable=True)
    next_steps = Column(JSON, nullable=True)
    evidence = Column(JSON, nullable=True)               # trusted records the model cited
    injection_suspected = Column(Boolean, default=False) # by the model or the guards
    model_flagged_injection = Column(Boolean, default=False)
    overrides = Column(JSON, nullable=True)              # what the guards changed, and why
    context = Column(JSON, nullable=True)                # the trusted SOC records the model was given
    valid = Column(Boolean, default=True)                # False: unusable answer, escalated
    error = Column(Text, nullable=True)

    decision = Column(String(20), nullable=True)         # accepted | rejected, by an analyst
    decided_by = Column(String(100), nullable=True)

    created_at = Column(DateTime(timezone=True), server_default=func.now())
    completed_at = Column(DateTime(timezone=True), nullable=True)

    incident = relationship("Incident", back_populates="triage_results")
