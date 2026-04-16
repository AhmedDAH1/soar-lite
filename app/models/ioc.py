from sqlalchemy import Column, Integer, String, Text, Boolean, ForeignKey, Enum as SQLEnum
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from sqlalchemy import DateTime
import enum
from app.database import Base


class IOCType(enum.Enum):
    """Types of Indicators of Compromise"""
    IP = "ip"
    DOMAIN = "domain"
    EMAIL = "email"
    MD5 = "md5"
    SHA256 = "sha256"
    URL = "url"


class IOC(Base):
    """
    Indicator of Compromise (IOC) extracted from alerts.
    
    IOCs are observable artifacts like IPs, domains, hashes that indicate
    malicious activity. They're automatically extracted from alert data
    and can be enriched with threat intelligence.
    """
    __tablename__ = "iocs"
    
    id = Column(Integer, primary_key=True, index=True)
    
    # Link to parent incident
    incident_id = Column(Integer, ForeignKey("incidents.id"), nullable=False)
    
    # IOC data
    type = Column(SQLEnum(IOCType), nullable=False)
    value = Column(String(500), nullable=False, index=True)  # Indexed for fast lookups
    
    # Enrichment data (populated in Milestone 3)
    enrichment_data = Column(Text, nullable=True)  # JSON string from APIs
    is_malicious = Column(Boolean, default=False)
    
    # Metadata
    extracted_from = Column(String(50), nullable=True)  # e.g., "alert_title", "alert_description"
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationship
    incident = relationship("Incident", back_populates="iocs")