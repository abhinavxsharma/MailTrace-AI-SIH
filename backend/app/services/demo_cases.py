"""
Controlled deterministic demonstration cases for MAILTRACE AI SIH evaluation.

Provides three reproducible test cases:
1. Legitimate business communication (low risk, valid authentication)
2. BEC / Executive Invoice Fraud (CFO spoofing, reply-to mismatch, DMARC fail, phishing URL)
3. Related Campaign Variant (shares Reply-To, source IP, and destination domain with Case 2 to demonstrate multi-case correlation)

Documentation note:
IPs such as 198.51.100.42, 203.0.113.80, and 192.0.2.44 are RFC 5737
documentation/test networks used safely for controlled evaluation.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List
from sqlalchemy.orm import Session

from backend.app.schemas.analysis import NormalizedEmail
from backend.app.services.analysis_pipeline import AnalysisPipeline, get_pipeline


def get_demo_case_1_legitimate() -> NormalizedEmail:
    """Case 1: Legitimate Internal Communication."""
    return NormalizedEmail(
        provider="gmail",
        provider_message_id="sih-demo-01-legitimate",
        sender="Finance Office <finance@company-internal.org>",
        recipient="team@company-internal.org",
        subject="Monthly expense report — September",
        body=(
            "Hello team, the September monthly expense report is attached for your review. "
            "Please use the normal internal finance portal if you need to submit corrections. "
            "Regards, Finance Office."
        ),
        headers=[
            {"name": "From", "value": "Finance Office <finance@company-internal.org>"},
            {"name": "To", "value": "team@company-internal.org"},
            {"name": "Reply-To", "value": "finance@company-internal.org"},
            {"name": "Return-Path", "value": "<finance@company-internal.org>"},
            {"name": "Subject", "value": "Monthly expense report — September"},
            {"name": "Date", "value": "Wed, 17 Sep 2026 09:30:00 +0000"},
            {"name": "Message-ID", "value": "<msg-2026-legit-001@company-internal.org>"},
            {"name": "Authentication-Results", "value": "mx.google.com; dkim=pass header.i=@company-internal.org; spf=pass smtp.mailfrom=company-internal.org; dmarc=pass header.from=company-internal.org"},
            {"name": "Received", "value": "from mail-out.company-internal.org ([198.51.100.10]) by mx.google.com with ESMTPS"},
        ],
        received_at=datetime(2026, 9, 17, 9, 30, 0, tzinfo=timezone.utc),
    )


def get_demo_case_2_bec() -> NormalizedEmail:
    """Case 2: BEC / Executive Invoice Fraud."""
    return NormalizedEmail(
        provider="gmail",
        provider_message_id="sih-demo-02-bec-fraud",
        sender="CFO <cfo@acme-finance.com>",
        recipient="accounts-payable@target-enterprise.com",
        subject="URGENT: Executive Wire Transfer Request — Process Immediately",
        body=(
            "This is an urgent request from the CFO. Our vendor banking details were updated today. "
            "Please process the transfer immediately for the outstanding invoice. "
            "Do not call to confirm as I am currently in board meetings all afternoon. "
            "Review and verify the invoice here: https://secure-acme-login.example/verify-invoice"
        ),
        headers=[
            {"name": "From", "value": "CFO <cfo@acme-finance.com>"},
            {"name": "Return-Path", "value": "<billing@notify-acme.co>"},
            {"name": "Reply-To", "value": "<acme.invoice.alert@gmail.com>"},
            {"name": "To", "value": "accounts-payable@target-enterprise.com"},
            {"name": "Subject", "value": "URGENT: Executive Wire Transfer Request — Process Immediately"},
            {"name": "Date", "value": "Thu, 18 Sep 2026 14:15:00 +0000"},
            {"name": "Message-ID", "value": "<mid-2026-bec-9941@notify-acme.co>"},
            {
                "name": "Authentication-Results",
                "value": "mx.google.com; spf=pass smtp.mailfrom=notify-acme.co; dkim=pass header.d=notify-acme.co; dmarc=fail header.from=acme-finance.com",
            },
            {
                "name": "Received",
                "value": "from relay-07.cloud ([198.51.100.42]) by mx.google.com with ESMTPS id abc123bec",
            },
        ],
        received_at=datetime(2026, 9, 18, 14, 15, 0, tzinfo=timezone.utc),
    )


def get_demo_case_3_campaign_variant() -> NormalizedEmail:
    """Case 3: Related Campaign Variant (Correlated to Case 2 via shared indicators)."""
    return NormalizedEmail(
        provider="gmail",
        provider_message_id="sih-demo-03-campaign-variant",
        sender="Finance Operations <finance-desk@acme-finance.com>",
        recipient="billing@target-enterprise.com",
        subject="URGENT: Outstanding Vendor Settlement Remittance",
        body=(
            "Urgent reminder from Finance regarding the updated settlement schedule. "
            "Please verify transfer confirmation through the secure vendor portal: "
            "https://secure-acme-login.example/portal/settlement-statement "
            "Process the payment immediately before close of business."
        ),
        headers=[
            {"name": "From", "value": "Finance Operations <finance-desk@acme-finance.com>"},
            {"name": "Return-Path", "value": "<remittance@notify-acme.co>"},
            {"name": "Reply-To", "value": "<acme.invoice.alert@gmail.com>"},
            {"name": "To", "value": "billing@target-enterprise.com"},
            {"name": "Subject", "value": "URGENT: Outstanding Vendor Settlement Remittance"},
            {"name": "Date", "value": "Fri, 19 Sep 2026 10:05:00 +0000"},
            {"name": "Message-ID", "value": "<mid-2026-camp-8812@notify-acme.co>"},
            {
                "name": "Authentication-Results",
                "value": "mx.google.com; spf=pass smtp.mailfrom=notify-acme.co; dkim=pass header.d=notify-acme.co; dmarc=fail header.from=acme-finance.com",
            },
            {
                "name": "Received",
                "value": "from relay-07.cloud ([198.51.100.42]) by mx.google.com with ESMTPS id def456camp",
            },
        ],
        received_at=datetime(2026, 9, 19, 10, 5, 0, tzinfo=timezone.utc),
    )


def get_all_demo_templates() -> List[Dict[str, Any]]:
    """Return all three demo case definitions with descriptive metadata for UI display."""
    return [
        {
            "id": "case-1",
            "title": "Case 1: Legitimate Internal Email",
            "category": "BENIGN",
            "description": "Legitimate expense report with valid SPF/DKIM/DMARC alignment and clean reputation.",
            "email": get_demo_case_1_legitimate().model_dump(mode="json"),
        },
        {
            "id": "case-2",
            "title": "Case 2: BEC / Executive Invoice Fraud",
            "category": "MALICIOUS",
            "description": "Urgent CFO impersonation, notify-acme.co return path, Gmail reply-to, and credential phishing URL.",
            "email": get_demo_case_2_bec().model_dump(mode="json"),
        },
        {
            "id": "case-3",
            "title": "Case 3: Related Campaign Variant",
            "category": "MALICIOUS (CAMPAIGN)",
            "description": "Campaign email sharing Reply-To, Relay IP, and domain with Case 2. Demonstrates graph correlation and campaign clustering.",
            "email": get_demo_case_3_campaign_variant().model_dump(mode="json"),
        },
    ]


def seed_demo_cases(db: Session, pipeline: AnalysisPipeline | None = None) -> List[Dict[str, Any]]:
    """Run all 3 controlled demo cases sequentially through the real analysis pipeline."""
    pipe = pipeline or get_pipeline()
    results: List[Dict[str, Any]] = []

    for demo_email in [
        get_demo_case_1_legitimate(),
        get_demo_case_2_bec(),
        get_demo_case_3_campaign_variant(),
    ]:
        case, stage_results = pipe.run(db=db, email=demo_email)
        results.append({
            "case_id": case.case_id,
            "provider_message_id": case.provider_message_id,
            "subject": case.subject,
            "status": case.status,
            "classification": case.classification,
            "ai_confidence": case.ai_confidence,
            "risk_score": case.risk_score,
            "campaign_detected": stage_results.get("correlation", {}).get("campaign_detected", False),
            "cluster_id": stage_results.get("correlation", {}).get("cluster_id"),
        })

    return results
