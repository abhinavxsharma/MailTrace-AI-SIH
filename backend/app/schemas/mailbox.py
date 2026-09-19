"""Pydantic schemas for mailbox data models."""

from datetime import datetime
from pydantic import BaseModel, ConfigDict, Field
from backend.app.models.enums import MailboxStatus


class MailboxBase(BaseModel):
    """Base schema for mailbox attributes."""

    provider: str = Field(..., min_length=1, description="Mailbox service provider, e.g. gmail, outlook")
    account_email: str = Field(..., min_length=3, description="Account email address")
    status: MailboxStatus = Field(default=MailboxStatus.CONNECTED, description="Current mailbox status")


class MailboxCreate(MailboxBase):
    """Schema for registering a new mailbox."""
    pass


class MailboxStatusUpdate(BaseModel):
    """Schema for updating mailbox status."""

    status: MailboxStatus = Field(..., description="Target status for the mailbox")


class MailboxRead(MailboxBase):
    """Response schema for mailbox details."""

    id: int
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)
