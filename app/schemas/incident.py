from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime
from app.schemas.alert import AlertResponse
from app.schemas.ioc import IOCResponse
from app.schemas.action import ActionResponse


class IncidentBase(BaseModel):
    """Base incident schema with common fields"""
    title: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    severity: str
    status: str


class IncidentCreate(IncidentBase):
    """Schema for creating incidents (currently not used - incidents auto-created from alerts)"""
    pass


class IncidentUpdate(BaseModel):
    """Schema for updating incidents - all fields optional"""
    title: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None
    severity: Optional[str] = None
    status: Optional[str] = None


class IncidentResponse(BaseModel):
    """Basic incident response (for lists)"""
    id: int
    title: str
    description: Optional[str]
    severity: str
    status: str
    created_at: datetime
    updated_at: Optional[datetime]
    
    class Config:
        from_attributes = True


class IncidentDetailResponse(IncidentResponse):
    """Detailed incident response with relationships"""
    alerts: List[AlertResponse] = []
    iocs: List[IOCResponse] = []
    actions: List[ActionResponse] = []
    
    class Config:
        from_attributes = True