"""Pydantic schemas for case management."""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict, Field

from backend.app.models.enums import CaseStatus, Classification


class CaseBase(BaseModel):
    """Base schema for case properties."""

    provider: str = Field(..., min_length=1, description="Mailbox provider, e.g. gmail, outlook")
    provider_message_id: str = Field(..., min_length=1, description="Unique message ID provided by mailbox source")
    thread_id: Optional[str] = Field(default=None, description="Conversation thread identifier")
    sender: str = Field(..., min_length=1, description="Sender email address or header")
    recipient: str = Field(..., min_length=1, description="Recipient email address")
    subject: str = Field(default="", description="Email subject line")
    received_at: datetime = Field(..., description="Timestamp when the email was received")
    mailbox_id: Optional[int] = Field(default=None, description="Optional foreign key to associated mailbox")


class CaseCreate(CaseBase):
    """Schema for creating a new email threat case."""
    pass


class CaseStatusUpdate(BaseModel):
    """Schema for modifying the status of an existing case."""

    status: CaseStatus = Field(..., description="New lifecycle status")


class CaseAnalysisUpdate(BaseModel):
    """Schema for submitting or updating case assessment results."""

    classification: Classification = Field(..., description="Threat classification")
    ai_confidence: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Confidence score between 0.0 and 1.0",
    )
    risk_score: Optional[int] = Field(
        default=None,
        ge=0,
        le=100,
        description="Calculated risk score between 0 and 100",
    )


class CaseRead(CaseBase):
    """Response schema for case details."""

    id: int
    case_id: str
    status: CaseStatus
    classification: Classification
    ai_confidence: Optional[float] = None
    risk_score: Optional[int] = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)
