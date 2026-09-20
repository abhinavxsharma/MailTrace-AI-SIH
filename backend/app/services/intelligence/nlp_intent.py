"""
MAILTRACE AI — NLP Threat Intent Analysis Layer.

Extracts structured behavioral threat intent categories from email content to determine
what the message is attempting to compel the recipient to do (e.g. payment diversion,
credential theft, executive impersonation, high-pressure urgency).

Operates strictly in memory with sub-5ms performance for fast-path Pre-Open Scanning.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class NlpThreatIntent(BaseModel):
    """Structured threat intent determination with evidence and user-readable explanation."""

    intent: str = Field(..., description="Standardized threat intent category")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence score from 0.0 to 1.0")
    evidence: str = Field(..., description="Exact textual evidence or matched snippet from message")
    explanation: str = Field(..., description="User-facing, plain-language explanation of this intent")
    source: str = Field(default="nlp", description="Originating intelligence component")

    model_config = ConfigDict(from_attributes=True)


# Intent categories and compiled patterns
_INTENT_DEFINITIONS = [
    {
        "intent": "payment_diversion",
        "pattern": re.compile(
            r"\b(new\s+(?:bank|banking|account|wire)\s+details|update\s+(?:our\s+)?banking\s+details|"
            r"change\s+(?:of\s+)?(?:account|direct\s+deposit|wire\s+instructions?)|"
            r"remit\s+to\s+(?:the\s+)?new\s+account|updated\s+payment\s+instructions?|"
            r"revised\s+(?:banking|wire)\s+information|divert\s+(?:funds|payment))\b",
            re.IGNORECASE,
        ),
        "explanation": "Instructs the recipient to divert funds or update bank account routing details.",
        "base_confidence": 0.95,
    },
    {
        "intent": "financial_transfer",
        "pattern": re.compile(
            r"\b(wire\s+(?:transfer|details|payment|instructions?)|send\s+(?:the\s+)?funds|process\s+(?:a\s+)?payment|"
            r"bank\s+transfer|routing\s+number|swift\s+code|remittance\s+advice|"
            r"transfer\s+\$[\d,]+|remit\s+.*?\$[\d,]+|wire\s+\$[\d,]+|"
            r"transfer\s+of\s+funds|immediate\s+disbursement)\b",
            re.IGNORECASE,
        ),
        "explanation": "Requests or solicits a financial wire transfer or monetary payment.",
        "base_confidence": 0.92,
    },
    {
        "intent": "invoice_fraud",
        "pattern": re.compile(
            r"\b(overdue\s+invoice|outstanding\s+balance|unpaid\s+invoice|"
            r"invoice\s+(?:#|no\.?|num)?\s*[\w-]+\s+(?:is\s+due|past\s+due)|"
            r"payment\s+due\s+immediately|remit\s+invoice\s+payment|"
            r"statement\s+of\s+account|billing\s+adjustment)\b",
            re.IGNORECASE,
        ),
        "explanation": "Claims an unpaid or overdue invoice requires immediate settlement.",
        "base_confidence": 0.88,
    },
    {
        "intent": "password_reset_lure",
        "pattern": re.compile(
            r"\b(reset\s+your\s+password|password\s+reset\s+requested|"
            r"click\s+here\s+to\s+reset\s+(?:your\s+)?password|"
            r"temporary\s+password|your\s+password\s+has\s+expired|"
            r"change\s+password\s+immediately|password\s+expiry\s+notice)\b",
            re.IGNORECASE,
        ),
        "explanation": "Prompts the recipient to reset or update their account password.",
        "base_confidence": 0.93,
    },
    {
        "intent": "credential_harvesting",
        "pattern": re.compile(
            r"\b(verify\s+your\s+account|confirm\s+(?:your\s+)?credentials|"
            r"login\s+to\s+(?:restore|verify|unlock|confirm)|"
            r"sign\s+in\s+to\s+(?:continue|verify|review)|"
            r"authenticate\s+your\s+session|update\s+(?:your\s+)?login|"
            r"enter\s+your\s+(?:password|username|mfa\s+code))\b",
            re.IGNORECASE,
        ),
        "explanation": "Prompts the recipient to enter login credentials or verify their identity.",
        "base_confidence": 0.94,
    },
    {
        "intent": "account_takeover",
        "pattern": re.compile(
            r"\b(unauthorized\s+(?:access|activity|sign-in|login)|"
            r"account\s+(?:suspended|restricted|compromised|locked)|"
            r"security\s+alert:\s+unusual\s+activity|"
            r"your\s+account\s+will\s+be\s+(?:disabled|closed|deleted)|"
            r"suspicious\s+login\s+attempt\s+detected)\b",
            re.IGNORECASE,
        ),
        "explanation": "Simulates account compromise or imminent suspension to provoke panic.",
        "base_confidence": 0.91,
    },
    {
        "intent": "executive_impersonation",
        "pattern": re.compile(
            r"\b(sent\s+from\s+my\s+iphone|sent\s+from\s+my\s+ipad|"
            r"i\s+am\s+(?:currently\s+)?in\s+a\s+meeting|do\s+not\s+call\s+me|"
            r"executive\s+approval|keep\s+this\s+(?:strictly\s+)?confidential|"
            r"are\s+you\s+at\s+your\s+desk|need\s+you\s+to\s+handle\s+this\s+discreetly|"
            r"urgent\s+task\s+from\s+(?:the\s+)?ceo|per\s+my\s+instructions)\b",
            re.IGNORECASE,
        ),
        "explanation": "Emulates executive communication habits (e.g. mobile device, secrecy, out-of-band instructions).",
        "base_confidence": 0.86,
    },
    {
        "intent": "urgency_coercion",
        "pattern": re.compile(
            r"\b(urgent(?:ly)?|immediate(?:ly)?|action\s+required|"
            r"within\s+(?:24|12|48|2)\s+hours?|before\s+(?:4\s*pm|close\s+of\s+business|cob)|"
            r"final\s+notice|time-sensitive|strict\s+deadline|"
            r"immediate\s+response\s+needed|process\s+without\s+delay)\b",
            re.IGNORECASE,
        ),
        "explanation": "Uses high-pressure time limits and coercion to rush decision making.",
        "base_confidence": 0.89,
    },
    {
        "intent": "callback_social_engineering",
        "pattern": re.compile(
            r"\b(call\s+(?:us\s+)?immediately\s+at|reach\s+our\s+fraud\s+desk|"
            r"contact\s+our\s+support\s+line\s+at|call\s+toll-free|"
            r"if\s+you\s+did\s+not\s+authorize\s+this,\s+call)\b",
            re.IGNORECASE,
        ),
        "explanation": "Directs the recipient to call a fraudulent phone number for telephone-based social engineering.",
        "base_confidence": 0.90,
    },
    {
        "intent": "attachment_delivery",
        "pattern": re.compile(
            r"\b(see\s+attached\s+(?:invoice|receipt|document|file)|"
            r"review\s+(?:the\s+)?attached|open\s+(?:the\s+)?(?:attachment|zip|pdf)|"
            r"download\s+the\s+attached\s+file|attached\s+statement)\b",
            re.IGNORECASE,
        ),
        "explanation": "Coaxes recipient to open an email attachment that may carry malicious payloads.",
        "base_confidence": 0.82,
    },
    {
        "intent": "malware_delivery",
        "pattern": re.compile(
            r"\b(enable\s+content|enable\s+macros|install\s+the\s+update|"
            r"download\s+the\s+(?:viewer|security\s+patch|installer)|"
            r"run\s+the\s+executable|open\s+the\s+enclosed\s+iso)\b",
            re.IGNORECASE,
        ),
        "explanation": "Directs recipient to execute or enable potentially malicious code or macro-enabled documents.",
        "base_confidence": 0.94,
    },
    {
        "intent": "data_request",
        "pattern": re.compile(
            r"\b(send\s+(?:me\s+)?(?:the\s+)?(?:employee\s+)?w-?2s?|"
            r"payroll\s+records|employee\s+(?:list|directory|ssns?)|"
            r"customer\s+(?:database|pii|credit\s+card\s+records)|"
            r"confidential\s+salary\s+information)\b",
            re.IGNORECASE,
        ),
        "explanation": "Requests exfiltration of sensitive organizational data, payroll, or employee PII.",
        "base_confidence": 0.92,
    },
]


class NlpThreatIntentEngine:
    """
    High-speed, memory-only NLP intent classifier extracting structured threat intents.
    """

    def analyze(
        self,
        subject: str,
        body: str,
        sender_display_name: Optional[str] = None,
    ) -> List[NlpThreatIntent]:
        """
        Extract behavioral threat intents present in email subject and content.

        Args:
            subject: Email subject string.
            body: Email body or snippet.
            sender_display_name: Optional sender display name.

        Returns:
            List of detected NlpThreatIntent items.
        """
        text = f"{subject}\n{body}"
        if sender_display_name:
            text = f"{sender_display_name}: {text}"

        intents: List[NlpThreatIntent] = []
        seen_intents: set[str] = set()

        for item in _INTENT_DEFINITIONS:
            intent_name = item["intent"]
            match = item["pattern"].search(text)
            if match:
                matched_snippet = match.group(0).strip()
                # Compute contextual confidence bump if matched in subject line
                confidence = item["base_confidence"]
                if item["pattern"].search(subject):
                    confidence = min(0.99, confidence + 0.04)

                intents.append(
                    NlpThreatIntent(
                        intent=intent_name,
                        confidence=round(confidence, 2),
                        evidence=f"Matched trigger: '{matched_snippet}'",
                        explanation=item["explanation"],
                        source="nlp",
                    )
                )
                seen_intents.add(intent_name)

        return intents


# Global default engine instance
_nlp_intent_engine = NlpThreatIntentEngine()


def extract_threat_intents(
    subject: str,
    body: str,
    sender_display_name: Optional[str] = None,
) -> List[NlpThreatIntent]:
    """Helper returning detected behavioral threat intents from email content."""
    return _nlp_intent_engine.analyze(
        subject=subject,
        body=body,
        sender_display_name=sender_display_name,
    )
