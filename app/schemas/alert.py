from pydantic import BaseModel, Field
from typing import Optional, Dict, Any
from datetime import datetime


class AlertCreate(BaseModel):
    """
    Schema for creating a new alert via API.
    This is what clients send in POST /api/alerts
    """
    source: str = Field(..., min_length=1, max_length=100, description="Alert source (e.g., 'siem', 'edr')")
    title: str = Field(..., min_length=1, max_length=255, description="Alert title/summary")
    description: Optional[str] = Field(None, description="Detailed alert description")
    raw_data: Optional[Dict[str, Any]] = Field(None, description="Raw alert data from source")
    severity: Optional[str] = Field("medium", description="Incident severity (low/medium/high/critical)")


class AlertResponse(BaseModel):
    """
    Schema for alert responses.
    This is what the API returns after creating an alert.
    """
    id: int
    incident_id: int
    source: str
    title: str
    description: Optional[str]
    raw_data: Optional[Dict[str, Any]]
    created_at: datetime
    
    class Config:
        from_attributes = True  # Allows Pydantic to work with SQLAlchemy models