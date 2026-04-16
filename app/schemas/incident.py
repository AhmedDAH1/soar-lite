from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime


class IncidentResponse(BaseModel):
    """
    Schema for incident responses.
    """
    id: int
    title: str
    description: Optional[str]
    severity: str
    status: str
    created_at: datetime
    updated_at: Optional[datetime]
    
    class Config:
        from_attributes = True