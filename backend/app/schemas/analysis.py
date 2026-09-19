"""Pydantic schemas for analysis pipeline requests and results."""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field

from backend.app.models.enums import CaseStatus, Classification


class NormalizedEmail(BaseModel):
    """Normalized email payload ingested from connected mailboxes (Gmail/Outlook)."""

    provider: str = Field(..., min_length=1, description="Source provider identifier, e.g. gmail, outlook")
    provider_message_id: str = Field(..., min_length=1, description="Unique message ID assigned by mailbox provider")
    thread_id: Optional[str] = Field(default=None, description="Mailbox thread or conversation ID")
    sender: str = Field(..., min_length=1, description="Sender email address")
    recipient: str = Field(..., min_length=1, description="Recipient email address")
    subject: str = Field(default="", description="Email subject line")
    body: str = Field(default="", description="Extracted plaintext or sanitized email body content")
    headers: List[Any] = Field(default_factory=list, description="Extracted raw or structured email headers")
    received_at: Optional[datetime] = Field(default=None, description="Email reception timestamp")
    mailbox_id: Optional[int] = Field(default=None, description="Optional associated mailbox ID")


class AnalysisStartResponse(BaseModel):
    """Response returned when the analysis pipeline is initiated."""

    case_id: str = Field(..., description="Unique case identifier")
    status: CaseStatus = Field(..., description="Current case status, typically PROCESSING")
    message: str = Field(default="Analysis pipeline started", description="Status message")


class AnalysisResult(BaseModel):
    """Structured aggregate result of all pipeline analysis stages."""

    case_id: str = Field(..., description="Unique case identifier")
    status: CaseStatus = Field(..., description="Current case lifecycle status")
    classification: Classification = Field(..., description="Threat classification")
    ai_confidence: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    risk_score: Optional[int] = Field(default=None, ge=0, le=100)

    # Modular stage outputs
    forensics: Dict[str, Any] = Field(default_factory=dict, description="Forensics analysis findings")
    authentication: Dict[str, Any] = Field(default_factory=dict, description="Authentication analysis (SPF, DKIM, DMARC)")
    ml: Dict[str, Any] = Field(default_factory=dict, description="Machine learning threat detection outputs")
    intelligence: Dict[str, Any] = Field(default_factory=dict, description="Threat intelligence enrichment (DNS, RDAP, GeoIP, reputation)")
    correlation: Dict[str, Any] = Field(default_factory=dict, description="Campaign and graph correlation analysis")
    risk: Dict[str, Any] = Field(default_factory=dict, description="Calculated risk score determination")

    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


class AnalysisRead(BaseModel):
    """Response schema for a persisted analysis record."""

    id: int
    case_id: int
    classification: Classification
    ai_confidence: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    risk_score: Optional[int] = Field(default=None, ge=0, le=100)

    forensics: Dict[str, Any] = Field(default_factory=dict)
    authentication: Dict[str, Any] = Field(default_factory=dict)
    ml: Dict[str, Any] = Field(default_factory=dict)
    intelligence: Dict[str, Any] = Field(default_factory=dict)
    correlation: Dict[str, Any] = Field(default_factory=dict)
    risk: Dict[str, Any] = Field(default_factory=dict)

    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)
