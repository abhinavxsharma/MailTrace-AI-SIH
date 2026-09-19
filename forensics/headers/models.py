"""
MAILTRACE AI — Typed domain models for Header Forensics.

This module defines Pydantic v2 models representing header forensic findings
and forensic results. Severity is strictly bounded to INFO, LOW, and MEDIUM.
No phishing, maliciousness verdicts, or risk scores are produced.
"""

from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import BaseModel, Field, field_validator

SeverityLevel = Literal["INFO", "LOW", "MEDIUM"]
VALID_SEVERITIES = {"INFO", "LOW", "MEDIUM"}


class HeaderForensicFinding(BaseModel):
    """
    Deterministic factual observation from header forensic analysis.

    Attributes:
        code: Unique finding identifier (e.g. 'FROM_REPLY_TO_MISMATCH').
        category: Forensic category ('identity', 'header_integrity', 'routing').
        severity: Bounded severity level ('INFO', 'LOW', or 'MEDIUM').
        description: Plain-text explanation of the factual observation.
        evidence: Dictionary of relevant evidence data (e.g. header values).
        related_headers: List of header names involved in this finding.
    """

    model_config = {"frozen": True}

    code: Annotated[str, Field(description="Finding code, e.g. 'FROM_REPLY_TO_MISMATCH'")]
    category: Annotated[
        str, Field(description="Finding category, e.g. 'identity', 'header_integrity', 'routing'")
    ]
    severity: Annotated[SeverityLevel, Field(description="Severity: INFO, LOW, or MEDIUM")]
    description: Annotated[str, Field(description="Factual description of the finding")]
    evidence: Annotated[
        dict[str, Any], Field(default_factory=dict, description="Key-value evidence details")
    ]
    related_headers: Annotated[
        list[str], Field(default_factory=list, description="Headers involved in the finding")
    ]

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v: str) -> str:
        upper = v.upper()
        if upper not in VALID_SEVERITIES:
            raise ValueError(
                f"Invalid severity {v!r}. Severity must be one of {sorted(VALID_SEVERITIES)}"
            )
        return upper


class HeaderForensicResult(BaseModel):
    """
    Aggregated result of header forensic analysis for an email.

    Contains purely factual findings with no verdicts or risk scores.
    """

    model_config = {"frozen": True}

    findings: Annotated[
        list[HeaderForensicFinding],
        Field(default_factory=list, description="List of forensic findings"),
    ]
    total_findings: Annotated[
        int, Field(default=0, description="Total count of findings")
    ] = 0
    has_anomalies: Annotated[
        bool, Field(default=False, description="True if any LOW or MEDIUM findings exist")
    ] = False
