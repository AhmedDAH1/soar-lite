from sqlalchemy import Column, Integer, String, Text, DateTime, Enum
from sqlalchemy.sql import func
import enum
from app.database import Base


class SeverityEnum(enum.Enum):
    """Incident severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class StatusEnum(enum.Enum):
    """Incident lifecycle status"""
    NEW = "new"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    RESOLVED = "resolved"


class Incident(Base):
    """
    Core incident model representing a security event under investigation.
    Maps to the 'incidents' table in the database.
    """
    __tablename__ = "incidents"
    
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    
    severity = Column(
        Enum(SeverityEnum),
        default=SeverityEnum.MEDIUM,
        nullable=False
    )
    
    status = Column(
        Enum(StatusEnum),
        default=StatusEnum.NEW,
        nullable=False
    )
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())