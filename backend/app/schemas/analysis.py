"""Pydantic schemas for analysis results."""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict, Field

from backend.app.models.enums import Classification


class AnalysisRead(BaseModel):
    """Response schema for case threat analysis determination."""

    id: int
    case_id: int
    classification: Classification
    ai_confidence: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    risk_score: Optional[int] = Field(default=None, ge=0, le=100)
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)
