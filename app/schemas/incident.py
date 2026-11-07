from datetime import datetime

from pydantic import BaseModel, Field

from app.schemas.action import ActionResponse
from app.schemas.alert import AlertResponse
from app.schemas.ioc import IOCResponse


class IncidentBase(BaseModel):
    """Base incident schema with common fields"""
    title: str = Field(..., min_length=1, max_length=255)
    description: str | None = None
    severity: str
    status: str


class IncidentCreate(IncidentBase):
    """Schema for creating incidents (currently not used - incidents auto-created from alerts)"""
    pass


class IncidentUpdate(BaseModel):
    """Schema for updating incidents - all fields optional"""
    title: str | None = Field(None, min_length=1, max_length=255)
    description: str | None = None
    severity: str | None = None
    status: str | None = None


class IncidentResponse(BaseModel):
    """Basic incident response (for lists)"""
    id: int
    title: str
    description: str | None
    severity: str
    status: str
    created_at: datetime
    updated_at: datetime | None

    class Config:
        from_attributes = True


class IncidentDetailResponse(IncidentResponse):
    """Detailed incident response with relationships"""
    alerts: list[AlertResponse] = []
    iocs: list[IOCResponse] = []
    actions: list[ActionResponse] = []

    class Config:
        from_attributes = True
