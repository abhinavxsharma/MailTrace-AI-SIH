"""Pydantic schemas for normalized mailbox event notifications."""

from datetime import datetime
from enum import Enum
from typing import Optional
from pydantic import BaseModel, ConfigDict, Field


class MailEventType(str, Enum):
    """Types of mailbox change notifications."""

    NEW_MESSAGE = "NEW_MESSAGE"
    MESSAGE_UPDATED = "MESSAGE_UPDATED"
    MESSAGE_DELETED = "MESSAGE_DELETED"


class MailEventStatus(str, Enum):
    """Ingestion processing status for received mail events."""

    ACCEPTED = "accepted"
    DUPLICATE = "duplicate"
    REJECTED = "rejected"


class MailEvent(BaseModel):
    """Normalized mailbox notification event received from email providers."""

    provider: str = Field(..., min_length=1, description="Source provider identifier, e.g. gmail, outlook")
    account_email: str = Field(..., min_length=3, description="Account email associated with the mailbox")
    provider_message_id: str = Field(..., min_length=1, description="Provider's unique message identifier")
    thread_id: Optional[str] = Field(default=None, description="Optional thread or conversation ID")
    event_type: MailEventType = Field(default=MailEventType.NEW_MESSAGE, description="Mail event notification type")
    received_at: Optional[datetime] = Field(default=None, description="Event occurrence timestamp")


class MailEventResponse(BaseModel):
    """Response returned upon mailbox event ingestion."""

    status: MailEventStatus = Field(..., description="Processing status: accepted, duplicate, or rejected")
    provider: str = Field(..., description="Mailbox provider")
    provider_message_id: str = Field(..., description="Provider message ID")
    case_id: Optional[str] = Field(default=None, description="Assigned or existing case ID")
    mailbox_id: Optional[int] = Field(default=None, description="Associated internal mailbox ID")
    message: str = Field(default="Event accepted for processing", description="Descriptive status message")

    model_config = ConfigDict(from_attributes=True)
