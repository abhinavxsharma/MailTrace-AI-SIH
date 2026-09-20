"""Pydantic schemas for mailbox threat alerts."""

from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, ConfigDict, Field

from backend.app.models.enums import AlertStatus


class SecurityAlertBase(BaseModel):
    """Base schema for a security alert."""

    mailbox_id: int = Field(..., description="Connected mailbox database ID")
    message_id: str = Field(..., description="Provider message ID")
    thread_id: Optional[str] = Field(default=None, description="Provider thread ID")
    sender: str = Field(..., description="Sender email address")
    sender_name: Optional[str] = Field(default=None, description="Sender display name")
    subject: str = Field(..., description="Subject line of the email")
    verdict: str = Field(..., description="Threat verdict: BENIGN, SUSPICIOUS, MALICIOUS")
    risk_score: int = Field(..., ge=0, le=100, description="Normalized risk score from 0 to 100")
    risk_level: str = Field(..., description="Categorical risk tier: LOW, MEDIUM, HIGH, CRITICAL")
    confidence: float = Field(default=0.0, ge=0.0, le=1.0, description="Model confidence score")
    title: str = Field(..., description="Concise human-readable alert title")
    summary: str = Field(..., description="Explainable threat summary")
    reasons: List[str] = Field(default_factory=list, description="User-facing security explanations")
    indicators: List[str] = Field(default_factory=list, description="Security indicator tags")
    recommended_action: str = Field(
        default="Review email security preview before opening.",
        description="Recommended protective action",
    )
    status: AlertStatus = Field(default=AlertStatus.UNREAD, description="Alert status")


class SecurityAlertCreate(SecurityAlertBase):
    """Schema for creating a security alert."""

    case_id: Optional[int] = Field(default=None, description="Linked investigation case ID")


class SecurityAlertStatusUpdate(BaseModel):
    """Schema for updating alert status."""

    status: AlertStatus = Field(..., description="New status for the alert")


class SecurityAlertRead(BaseModel):
    """Read schema representing a stored security alert."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    alert_id: str
    mailbox_id: int
    message_id: str
    thread_id: Optional[str] = None
    case_id: Optional[int] = None
    sender: str
    sender_name: Optional[str] = None
    subject: str
    verdict: str
    risk_score: int
    risk_level: str
    confidence: float
    title: str
    summary: str
    reasons: List[str] = Field(default_factory=list)
    indicators: List[str] = Field(default_factory=list)
    recommended_action: str
    status: str
    created_at: datetime
    updated_at: datetime
