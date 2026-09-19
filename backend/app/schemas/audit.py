"""Pydantic schemas for case audit events."""

from datetime import datetime
from pydantic import BaseModel, ConfigDict


class AuditEventRead(BaseModel):
    """Response schema for case audit trail events."""

    id: int
    case_id: int
    event_type: str
    message: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
