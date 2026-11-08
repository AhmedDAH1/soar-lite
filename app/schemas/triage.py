from datetime import datetime
from typing import Any

from pydantic import BaseModel


class TriageSummary(BaseModel):
    """The AI suggestion as the incident list shows it."""
    status: str
    verdict: str | None = None
    severity: str | None = None
    injection_suspected: bool | None = False
    decision: str | None = None

    class Config:
        from_attributes = True


class TriageResponse(TriageSummary):
    id: int
    incident_id: int
    mode: str
    model: str | None = None
    confidence: float | None = None
    reasoning: str | None = None
    next_steps: list[str] | None = None
    evidence: list[str] | None = None
    model_flagged_injection: bool | None = False
    overrides: list[str] | None = None
    context: dict[str, Any] | None = None
    valid: bool | None = True
    error: str | None = None
    decided_by: str | None = None
    created_at: datetime | None = None
    completed_at: datetime | None = None
