"""Pydantic schemas for the Pre-Open Threat Scan security preview."""

from __future__ import annotations

from datetime import datetime
from typing import Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field

from backend.app.models.enums import Classification
from backend.app.services.intelligence.nlp_entities import ExtractedEntity
from backend.app.services.intelligence.nlp_intent import NlpThreatIntent
from backend.app.services.risk.levels import RiskLevel


class AuthenticationSummary(BaseModel):
    """Summarized cryptographic email authentication results."""

    spf: str = Field(default="NONE", description="SPF validation status (PASS, FAIL, SOFTFAIL, NONE)")
    dkim: str = Field(default="NONE", description="DKIM digital signature status (PASS, FAIL, NONE)")
    dmarc: str = Field(default="NONE", description="DMARC policy evaluation status (PASS, FAIL, NONE)")
    authenticated: bool = Field(default=False, description="Whether the message passes baseline authentication")


class PreOpenScanResponse(BaseModel):
    """Fast, lightweight security preview for an email before the user opens it."""

    message_id: str = Field(..., description="Message identifier")
    thread_id: Optional[str] = Field(default=None, description="Thread or conversation identifier")
    sender: str = Field(..., description="Sender email address")
    sender_name: Optional[str] = Field(default=None, description="Sender display name if present")
    subject: str = Field(default="", description="Email subject line")
    received_at: Optional[datetime] = Field(default=None, description="Message reception timestamp")

    # Threat verdict & scoring
    verdict: Classification = Field(
        ...,
        description="Immediate threat classification (BENIGN, SUSPICIOUS, MALICIOUS, PENDING)",
    )
    risk_score: int = Field(
        ...,
        ge=0,
        le=100,
        description="Deterministic normalized risk score from 0 (clean) to 100 (critical threat)",
    )
    risk_level: RiskLevel = Field(
        ...,
        description="Risk severity level (LOW, MEDIUM, HIGH, CRITICAL)",
    )
    confidence: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Confidence score from the AI threat classification model",
    )

    # Explainable insights
    reasons: List[str] = Field(
        default_factory=list,
        description="Concise, user-facing reasons explaining why this score was assigned",
    )
    indicators: List[str] = Field(
        default_factory=list,
        description="Technical indicators triggered during pre-open analysis",
    )
    authentication_summary: AuthenticationSummary = Field(
        default_factory=AuthenticationSummary,
        description="Summary of SPF, DKIM, and DMARC status",
    )
    recommended_action: str = Field(
        ...,
        description="Actionable user guidance for handling this email safely",
    )
    can_investigate: bool = Field(
        default=True,
        description="Whether deep forensic analysis and graph correlation is available",
    )
    nlp_intents: List[NlpThreatIntent] = Field(
        default_factory=list,
        description="Structured behavioral threat intents extracted by the NLP layer",
    )
    extracted_entities: List[ExtractedEntity] = Field(
        default_factory=list,
        description="High-priority structured entities extracted from email content",
    )
    breakdown: Optional[Dict[str, int]] = Field(
        default=None,
        description="Category risk score breakdown (ai_threat, identity, authentication, etc.)",
    )

    model_config = ConfigDict(from_attributes=True)
