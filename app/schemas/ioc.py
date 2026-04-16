from pydantic import BaseModel
from datetime import datetime
from typing import Optional


class IOCResponse(BaseModel):
    """Schema for IOC API responses"""
    id: int
    incident_id: int
    type: str
    value: str
    extracted_from: Optional[str]
    is_malicious: bool
    created_at: datetime
    
    class Config:
        from_attributes = True