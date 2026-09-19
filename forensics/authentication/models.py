"""
MAILTRACE AI — Domain models for Email Authentication Verification.

This module defines immutable (frozen) Pydantic v2 models representing
SPF, DKIM, DMARC, and domain alignment verification results, along with
upstream Authentication-Results header discrepancies.
"""

from __future__ import annotations

from typing import Annotated, Any

from pydantic import BaseModel, Field


class SpfResult(BaseModel):
    """
    Structured result of SPF verification.

    Attributes:
        domain: Envelope sender / Return-Path domain checked.
        ip: Connecting IP evaluated, or None if unavailable.
        policy: Raw SPF TXT record evaluated, or None if not found.
        status: Explicit SPF evaluation status (PASS, FAIL, SOFTFAIL, NEUTRAL,
                NONE, TEMPERROR, PERMERROR, UNAVAILABLE, NOT_EVALUATED).
        reason: Human-readable explanation of the evaluation outcome.
        evidence: Dictionary containing mechanism match details and lookups.
        error: Error description if a lookup or evaluation failed.
    """

    model_config = {"frozen": True}

    domain: Annotated[str, Field(description="Domain checked for SPF policy")]
    ip: Annotated[str | None, Field(default=None, description="Connecting IP checked")] = None
    policy: Annotated[str | None, Field(default=None, description="SPF record policy string")] = None
    status: Annotated[
        str,
        Field(
            description=(
                "Evaluation status: PASS, FAIL, SOFTFAIL, NEUTRAL, NONE, "
                "TEMPERROR, PERMERROR, UNAVAILABLE, NOT_EVALUATED"
            )
        ),
    ]
    reason: Annotated[str | None, Field(default=None, description="Explanation of the outcome")] = None
    evidence: Annotated[
        dict[str, Any],
        Field(default_factory=dict, description="Detailed evidence dictionary"),
    ]
    error: Annotated[str | None, Field(default=None, description="Error details if applicable")] = None


class DkimSignatureResult(BaseModel):
    """
    Structured verification result for an individual DKIM-Signature header.

    Attributes:
        domain: The signing domain ('d=' tag).
        selector: The selector ('s=' tag).
        result: Outcome ('valid', 'invalid', 'missing', 'unavailable', 'malformed').
        signature_valid: True if cryptographic signature successfully verified.
        error: Failure reason if signature was invalid or lookup failed.
        evidence: Tags and metadata extracted from the signature header.
    """

    model_config = {"frozen": True}

    domain: Annotated[str, Field(description="Signing domain (d= tag)")]
    selector: Annotated[str, Field(description="Selector (s= tag)")]
    result: Annotated[
        str,
        Field(
            description="Signature status: valid, invalid, missing, unavailable, malformed"
        ),
    ]
    signature_valid: Annotated[
        bool, Field(default=False, description="True if signature verified cryptographically")
    ] = False
    error: Annotated[str | None, Field(default=None, description="Error details if invalid")] = None
    evidence: Annotated[
        dict[str, Any],
        Field(default_factory=dict, description="DKIM signature tags and evidence"),
    ]


class DkimResult(BaseModel):
    """
    Aggregated DKIM verification result for an email.

    Supports messages with zero, one, or multiple DKIM signatures.
    """

    model_config = {"frozen": True}

    status: Annotated[
        str,
        Field(
            description="Overall DKIM status: valid, invalid, missing, unavailable, malformed"
        ),
    ]
    signatures: Annotated[
        list[DkimSignatureResult],
        Field(default_factory=list, description="Results for all evaluated signatures"),
    ]
    primary_domain: Annotated[
        str | None,
        Field(default=None, description="Signing domain of the primary/first valid signature"),
    ] = None
    error: Annotated[str | None, Field(default=None, description="Error details if applicable")] = None
    evidence: Annotated[
        dict[str, Any],
        Field(default_factory=dict, description="Aggregated DKIM evidence"),
    ]


class AlignmentResult(BaseModel):
    """
    DMARC domain alignment evaluation result.

    Evaluates whether the SPF envelope domain and DKIM signing domains align
    with the RFC 5322 From header domain under relaxed or strict semantics.
    """

    model_config = {"frozen": True}

    spf_aligned: Annotated[
        bool, Field(default=False, description="True if SPF domain aligns with From domain")
    ] = False
    dkim_aligned: Annotated[
        bool,
        Field(
            default=False,
            description="True if at least one valid DKIM signing domain aligns with From domain",
        ),
    ] = False
    spf_mode: Annotated[
        str, Field(default="relaxed", description="SPF alignment mode: 'relaxed' or 'strict'")
    ] = "relaxed"
    dkim_mode: Annotated[
        str, Field(default="relaxed", description="DKIM alignment mode: 'relaxed' or 'strict'")
    ] = "relaxed"
    from_domain: Annotated[str, Field(description="RFC 5322 From domain")]
    spf_domain: Annotated[
        str | None, Field(default=None, description="Return-Path / MailFrom domain evaluated")
    ] = None
    dkim_domains: Annotated[
        list[str],
        Field(
            default_factory=list,
            description="List of signing domains from valid DKIM signatures",
        ),
    ]
    evidence: Annotated[
        dict[str, Any],
        Field(default_factory=dict, description="Alignment comparison details"),
    ]


class DmarcResult(BaseModel):
    """
    Structured DMARC evaluation result.

    Combines SPF and DKIM verification, alignment results, and the published
    DMARC policy from DNS.
    """

    model_config = {"frozen": True}

    policy_domain: Annotated[
        str, Field(description="Domain where the DMARC policy record was discovered")
    ]
    policy: Annotated[
        str,
        Field(
            description="Published DMARC policy: 'none', 'quarantine', 'reject', or 'none_found'"
        ),
    ]
    disposition: Annotated[
        str,
        Field(
            description="Applied disposition action: 'none', 'quarantine', or 'reject'"
        ),
    ]
    spf_aligned: Annotated[
        bool, Field(default=False, description="SPF alignment status for DMARC")
    ] = False
    dkim_aligned: Annotated[
        bool, Field(default=False, description="DKIM alignment status for DMARC")
    ] = False
    status: Annotated[
        str,
        Field(
            description="DMARC evaluation status: PASS, FAIL, NONE, TEMPERROR, PERMERROR, NOT_EVALUATED"
        ),
    ]
    evidence: Annotated[
        dict[str, Any],
        Field(default_factory=dict, description="Detailed DMARC evaluation evidence"),
    ]
    error: Annotated[str | None, Field(default=None, description="Error details if applicable")] = None


class AuthenticationDiscrepancy(BaseModel):
    """
    Discrepancy between upstream Authentication-Results and local verification.
    """

    model_config = {"frozen": True}

    protocol: Annotated[str, Field(description="Protocol: 'spf', 'dkim', or 'dmarc'")]
    header_claimed_result: Annotated[
        str, Field(description="Claimed result in Authentication-Results header")
    ]
    locally_verified_result: Annotated[
        str, Field(description="Result computed by local verification")
    ]
    description: Annotated[str, Field(description="Explanation of the observed discrepancy")]


class AuthenticationResult(BaseModel):
    """
    Comprehensive structured evidence of email authentication verification.

    Contains verified SPF, DKIM, and DMARC results, alignment evaluations,
    and discrepancy analysis against the Authentication-Results header.
    """

    model_config = {"frozen": True}

    spf: Annotated[SpfResult, Field(description="SPF verification result")]
    dkim: Annotated[DkimResult, Field(description="DKIM verification result")]
    dmarc: Annotated[DmarcResult, Field(description="DMARC evaluation result")]
    alignment: Annotated[AlignmentResult, Field(description="Domain alignment evaluation result")]
    header_claims: Annotated[
        dict[str, Any],
        Field(
            default_factory=dict,
            description="Claims extracted from upstream Authentication-Results header",
        ),
    ]
    discrepancies: Annotated[
        list[AuthenticationDiscrepancy],
        Field(
            default_factory=list,
            description="Discrepancies between header claims and local verification",
        ),
    ]
    evidence: Annotated[
        dict[str, Any],
        Field(default_factory=dict, description="Aggregated authentication evidence"),
    ]
