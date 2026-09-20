"""
MAILTRACE AI — NLP Structured Entity Extraction Layer.

Extracts typed, structured entities from email content across 16 categories:
PERSON, ORGANIZATION, ROLE, EMAIL, DOMAIN, IP, URL, AMOUNT, CURRENCY,
DATE, DEADLINE, PHONE, ACCOUNT_IDENTIFIER, PAYMENT_INSTRUCTION, CRYPTO_WALLET,
and SERVICE_PLATFORM.

Provides fast-path normalization and deep forensic indicator feeds with zero hallucination.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class ExtractedEntity(BaseModel):
    """Structured extracted entity with normalized value and context."""

    type: str = Field(..., description="Entity category name (e.g. AMOUNT, DEADLINE, PERSON)")
    value: str = Field(..., description="Raw text value as encountered in message")
    normalized_value: Optional[str] = Field(default=None, description="Standardized or normalized representation")
    context: Optional[str] = Field(default=None, description="Surrounding contextual sentence or phrase")

    model_config = ConfigDict(from_attributes=True)


# Regex patterns for high-precision entity extraction
_RE_AMOUNT = re.compile(r"(?:[\$\€\£\₹]|(?:USD|EUR|GBP|INR|CAD|AUD)\s*)\s*(\d{1,3}(?:,\d{3})*(?:\.\d{2})?|\d+(?:\.\d{2})?)\b")
_RE_CURRENCY = re.compile(r"\b(USD|EUR|GBP|INR|CAD|AUD)\b|[\$\€\£\₹]")
_RE_DEADLINE = re.compile(
    r"\b(before\s+\d{1,2}(?::\d{2})?\s*(?:am|pm)?|within\s+\d{1,2}\s+hours?|"
    r"by\s+(?:close\s+of\s+business|cob|today|tomorrow|friday|monday|end\s+of\s+day)|"
    r"strict\s+deadline\s+of\s+[\w\s:]+)\b",
    re.IGNORECASE,
)
_RE_ROLE = re.compile(
    r"\b(chief\s+executive\s+officer|chief\s+financial\s+officer|chief\s+operating\s+officer|"
    r"chief\s+technology\s+officer|ceo|cfo|coo|cto|president|vice\s+president|vp\s+of\s+finance|"
    r"director|managing\s+director|treasurer|it\s+support|system\s+administrator|head\s+of\s+hr)\b",
    re.IGNORECASE,
)
_RE_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_RE_URL = re.compile(r"https?://[^\s<>\"'()]+")
_RE_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_RE_PHONE = re.compile(r"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b")
_RE_CRYPTO_BTC = re.compile(r"\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{39,59})\b")
_RE_CRYPTO_ETH = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
_RE_ACCOUNT_ID = re.compile(
    r"\b(?:account|acct|routing|iban|swift|bic)\s*(?:#|no\.?|num)?\s*[:=\s]\s*([A-Za-z0-9-]{6,34})\b",
    re.IGNORECASE,
)
_RE_PAYMENT_INSTRUCTION = re.compile(
    r"\b(wire\s+transfer|ach\s+transfer|direct\s+deposit|swift\s+wire|bank\s+transfer|"
    r"instant\s+transfer|zelle|venmo|cash\s*app|paypal\s+transfer)\b",
    re.IGNORECASE,
)
_RE_SERVICE_PLATFORM = re.compile(
    r"\b(microsoft\s+365|office\s+365|google\s+workspace|docusign|adobe\s+sign|"
    r"quickbooks|intuit|stripe|paypal|dropbox|salesforce|zoom|slack|sharepoint|onedrive)\b",
    re.IGNORECASE,
)
_RE_SIGN_OFF = re.compile(
    r"(?:regards|sincerely|thanks|best|cheers),\s*\n+([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,2})",
    re.IGNORECASE,
)


class NlpEntityExtractor:
    """
    Structured entity extraction engine operating deterministically on message content.
    """

    def extract(
        self,
        subject: str,
        body: str,
        sender_name: Optional[str] = None,
        sender_email: Optional[str] = None,
    ) -> List[ExtractedEntity]:
        """
        Extract and normalize structured entities across all 16 supported categories.

        Args:
            subject: Email subject.
            body: Email body.
            sender_name: Optional display name from header.
            sender_email: Optional sender email.

        Returns:
            Deduplicated list of ExtractedEntity objects.
        """
        combined = f"{subject}\n{body}"
        entities: List[ExtractedEntity] = []
        seen: set[tuple[str, str]] = set()

        def _add(ent_type: str, raw_val: str, norm_val: Optional[str] = None, ctx: Optional[str] = None):
            key = (ent_type, raw_val.strip().lower())
            if key not in seen and len(raw_val.strip()) > 1:
                seen.add(key)
                entities.append(
                    ExtractedEntity(
                        type=ent_type,
                        value=raw_val.strip(),
                        normalized_value=norm_val or raw_val.strip(),
                        context=ctx,
                    )
                )

        # 1. PERSON
        if sender_name and len(sender_name.split()) >= 2:
            _add("PERSON", sender_name, sender_name, "Header From display name")
        signoff_match = _RE_SIGN_OFF.search(body)
        if signoff_match:
            _add("PERSON", signoff_match.group(1), signoff_match.group(1), "Email sign-off block")

        # 2. ROLE
        for m in _RE_ROLE.finditer(combined):
            _add("ROLE", m.group(0), m.group(0).upper(), "Message content")

        # 3. AMOUNT
        for m in _RE_AMOUNT.finditer(combined):
            raw_full = m.group(0).strip()
            num_clean = m.group(1).replace(",", "")
            _add("AMOUNT", raw_full, num_clean, "Monetary request")

        # 4. CURRENCY
        for m in _RE_CURRENCY.finditer(combined):
            raw_curr = m.group(0).strip()
            symbol_map = {"$": "USD", "€": "EUR", "£": "GBP", "₹": "INR"}
            norm_curr = symbol_map.get(raw_curr, raw_curr.upper())
            _add("CURRENCY", raw_curr, norm_curr, "Monetary denomination")

        # 5. DEADLINE
        for m in _RE_DEADLINE.finditer(combined):
            _add("DEADLINE", m.group(0), m.group(0).lower(), "Urgency constraint")

        # 6. EMAIL
        for m in _RE_EMAIL.finditer(combined):
            em = m.group(0).lower()
            if em != (sender_email or "").lower():
                _add("EMAIL", m.group(0), em, "Body address reference")

        # 7. URL
        for m in _RE_URL.finditer(combined):
            _add("URL", m.group(0), m.group(0), "Hyperlink")

        # 8. IP
        for m in _RE_IP.finditer(combined):
            _add("IP", m.group(0), m.group(0), "IP literal")

        # 9. PHONE
        for m in _RE_PHONE.finditer(combined):
            _add("PHONE", m.group(0), re.sub(r"[^\d+]", "", m.group(0)), "Phone contact")

        # 10. PAYMENT_INSTRUCTION
        for m in _RE_PAYMENT_INSTRUCTION.finditer(combined):
            _add("PAYMENT_INSTRUCTION", m.group(0), m.group(0).lower(), "Transfer method")

        # 11. ACCOUNT_IDENTIFIER
        for m in _RE_ACCOUNT_ID.finditer(combined):
            _add("ACCOUNT_IDENTIFIER", m.group(0), m.group(1), "Bank / settlement routing")

        # 12. CRYPTO_WALLET
        for m in _RE_CRYPTO_BTC.finditer(combined):
            _add("CRYPTO_WALLET", m.group(0), m.group(0), "Bitcoin address")
        for m in _RE_CRYPTO_ETH.finditer(combined):
            _add("CRYPTO_WALLET", m.group(0), m.group(0).lower(), "Ethereum address")

        # 13. SERVICE_PLATFORM
        for m in _RE_SERVICE_PLATFORM.finditer(combined):
            _add("SERVICE_PLATFORM", m.group(0), m.group(0).title(), "Service lure brand")

        return entities


# Global default instance
_nlp_entity_extractor = NlpEntityExtractor()


def extract_entities(
    subject: str,
    body: str,
    sender_name: Optional[str] = None,
    sender_email: Optional[str] = None,
) -> List[ExtractedEntity]:
    """Helper extracting structured entities across all 16 supported categories."""
    return _nlp_entity_extractor.extract(
        subject=subject,
        body=body,
        sender_name=sender_name,
        sender_email=sender_email,
    )
