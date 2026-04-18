from pydantic import BaseModel, Field, field_validator
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


class WebhookAlert(BaseModel):
    """
    Schema for webhook-based alerts (flexible format).
    
    Maps external alert formats to our internal AlertCreate schema.
    Supports multiple naming conventions:
    - title/summary/alert_name
    - description/message/details
    - severity/priority/risk_level
    """
    # Required fields (flexible naming)
    source: str = Field(..., description="Source system (e.g., 'splunk', 'crowdstrike')")
    
    # Title variations (at least one required)
    title: Optional[str] = None
    summary: Optional[str] = None
    alert_name: Optional[str] = None
    
    # Description variations (optional)
    description: Optional[str] = None
    message: Optional[str] = None
    details: Optional[str] = None
    
    # Severity variations (optional)
    severity: Optional[str] = None
    priority: Optional[str] = None
    risk_level: Optional[str] = None
    
    # Catch-all for extra fields
    raw_data: Optional[Dict[str, Any]] = None
    
    @field_validator('source')
    @classmethod
    def validate_source(cls, v):
        """Ensure source is lowercase"""
        return v.lower()
    
    def to_alert_create(self) -> AlertCreate:
        """
        Convert webhook format to AlertCreate format.
        
        Intelligently maps flexible field names to standard schema.
        """
        # Determine title (try multiple field names)
        title = self.title or self.summary or self.alert_name
        if not title:
            title = f"Alert from {self.source}"
        
        # Determine description
        description = self.description or self.message or self.details
        
        # Determine severity
        severity = self.severity or self.priority or self.risk_level or "medium"
        
        # Normalize severity (different systems use different terms)
        severity_map = {
            'critical': 'critical',
            'high': 'high',
            'medium': 'medium',
            'low': 'low',
            # Common variations
            '1': 'low',
            '2': 'medium',
            '3': 'high',
            '4': 'critical',
            'info': 'low',
            'warning': 'medium',
            'error': 'high',
            'urgent': 'critical'
        }
        severity = severity_map.get(severity.lower(), 'medium')
        
        return AlertCreate(
            source=self.source,
            title=title,
            description=description,
            severity=severity,
            raw_data=self.raw_data or {}
        )


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
        from_attributes = True