from datetime import datetime

from pydantic import BaseModel


class ActionResponse(BaseModel):
    """Schema for action/timeline responses"""
    id: int
    incident_id: int
    action_type: str
    description: str
    playbook_name: str | None
    performed_by: str
    created_at: datetime

    class Config:
        from_attributes = True
