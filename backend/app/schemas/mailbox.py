from datetime import datetime
from typing import Optional
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
    latest_history_id: Optional[str] = None
    watch_expiration: Optional[datetime] = None
    has_credentials: bool = False
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ReportSpamResponse(BaseModel):
    """Response schema for reporting an email message as spam."""

    success: bool = Field(default=True, description="Indicates whether the report spam action succeeded")
    action: str = Field(default="REPORT_SPAM", description="Remediation action identifier")
    message_id: str = Field(..., description="Provider message ID reported")
    status: str = Field(default="REPORTED", description="Outcome status of spam classification")


class TrashMessageResponse(BaseModel):
    """Response schema for trashing an email message."""

    success: bool = Field(default=True, description="Indicates whether the trash action succeeded")
    action: str = Field(default="DELETE", description="Remediation action identifier")
    message_id: str = Field(..., description="Provider message ID moved to trash")
    status: str = Field(default="TRASHED", description="Outcome status confirming message moved to trash")


class BlockSenderResponse(BaseModel):
    """Response schema for blocking a sender via a Gmail filter."""

    success: bool = Field(default=True, description="Indicates whether sender block was applied or verified")
    action: str = Field(default="BLOCK_SENDER", description="Remediation action identifier")
    sender: str = Field(..., description="Canonical email address of the blocked sender")
    filter_id: Optional[str] = Field(None, description="Gmail filter ID created or existing")
    already_blocked: bool = Field(default=False, description="True if an active filter already existed for this sender")
