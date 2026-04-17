from pydantic import BaseModel
from datetime import datetime
from typing import Optional, Dict, Any
import json


class IOCResponse(BaseModel):
    """Schema for IOC API responses"""
    id: int
    incident_id: int
    type: str
    value: str
    extracted_from: Optional[str]
    is_malicious: bool
    enrichment_data: Optional[str]  # JSON string
    created_at: datetime
    
    class Config:
        from_attributes = True
    
    def dict(self, **kwargs):
        """Override dict() to parse enrichment_data JSON"""
        data = super().dict(**kwargs)
        
        # Parse enrichment_data from JSON string to dict
        if data.get("enrichment_data"):
            try:
                data["enrichment_data"] = json.loads(data["enrichment_data"])
            except json.JSONDecodeError:
                pass
        
        return data