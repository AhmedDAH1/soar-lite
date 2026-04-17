from pydantic import BaseModel
from datetime import datetime
from typing import Optional


class ActionResponse(BaseModel):
    """Schema for action/timeline responses"""
    id: int
    incident_id: int
    action_type: str
    description: str
    playbook_name: Optional[str]
    performed_by: str
    created_at: datetime
    
    class Config:
        from_attributes = True