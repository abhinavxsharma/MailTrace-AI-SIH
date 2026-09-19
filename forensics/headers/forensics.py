"""
MAILTRACE AI — Header forensics engine.

Performs deterministic, rule-based forensic inspection of email headers.
Produces structured factual observations with strictly bounded severities
(INFO, LOW, MEDIUM).

Does NOT produce:
- Malicious / benign verdicts
- Phishing verdicts
- Risk scores
- External network lookups (DNS, GeoIP, RDAP)
"""

from __future__ import annotations

import re
from typing import Any

from forensics.email_parser.models import ParsedEmail
from forensics.headers.models import HeaderForensicFinding, HeaderForensicResult

# Identity headers that must not appear more than once per RFC 5322 section 3.6
_SINGLE_OCCURRENCE_IDENTITY_HEADERS = {
    "from",
    "sender",
    "reply-to",
    "subject",
    "date",
    "message-id",
}

_MESSAGE_ID_SYNTAX = re.compile(r"^<[^@\s<>]+@[^@\s<>]+>$")


def analyze_headers(parsed_email: ParsedEmail) -> HeaderForensicResult:
    """
    Perform deterministic header forensic analysis on a ``ParsedEmail``.

    Evaluates 13 forensic rules and returns a ``HeaderForensicResult``
    containing structured factual findings.

    Args:
        parsed_email: The parsed email to inspect.

    Returns:
        A ``HeaderForensicResult`` containing all findings.
    """
    findings: list[HeaderForensicFinding] = []

    # 1. Missing From
    from_addr = parsed_email.from_address
    if from_addr is None or not from_addr.email:
        findings.append(
            HeaderForensicFinding(
                code="MISSING_FROM",
                category="identity",
                severity="MEDIUM",
                description="Mandatory From header is missing or empty.",
                evidence={},
                related_headers=["From"],
            )
        )

    # 2. Multiple From
    from_headers = parsed_email.get_headers("from")
    from_raw_val = parsed_email.get_header("from") or ""
    # Check if multiple addresses exist in From header or multiple From headers exist
    has_multiple_from_addrs = False
    if from_raw_val:
        # Check if comma-separated addresses exist in From
        parts = [p.strip() for p in from_raw_val.split(",") if p.strip()]
        if len(parts) > 1:
            has_multiple_from_addrs = True

    if len(from_headers) > 1 or has_multiple_from_addrs:
        findings.append(
            HeaderForensicFinding(
                code="MULTIPLE_FROM",
                category="identity",
                severity="MEDIUM",
                description="Multiple From addresses or multiple From headers detected.",
                evidence={
                    "from_header_count": len(from_headers),
                    "from_value": from_raw_val,
                },
                related_headers=["From"],
            )
        )

    # 3. From vs Reply-To mismatch
    if from_addr and from_addr.email and parsed_email.reply_to_addresses:
        for r_addr in parsed_email.reply_to_addresses:
            if r_addr.email and r_addr.email != from_addr.email:
                findings.append(
                    HeaderForensicFinding(
                        code="FROM_REPLY_TO_MISMATCH",
                        category="identity",
                        severity="MEDIUM",
                        description="From and Reply-To addresses differ.",
                        evidence={
                            "from": from_addr.email,
                            "reply_to": r_addr.email,
                        },
                        related_headers=["From", "Reply-To"],
                    )
                )
                break  # Record once

    # 4. From vs Return-Path mismatch
    return_path = parsed_email.return_path
    if (
        from_addr
        and from_addr.email
        and return_path
        and return_path.email
        and return_path.domain != from_addr.domain
    ):
        findings.append(
            HeaderForensicFinding(
                code="FROM_RETURN_PATH_MISMATCH",
                category="identity",
                severity="LOW",
                description="From and Return-Path domains differ.",
                evidence={
                    "from": from_addr.email,
                    "return_path": return_path.email,
                },
                related_headers=["From", "Return-Path"],
            )
        )

    # 5. From vs Sender mismatch
    sender = parsed_email.sender_address
    if (
        from_addr
        and from_addr.email
        and sender
        and sender.email
        and sender.email != from_addr.email
    ):
        findings.append(
            HeaderForensicFinding(
                code="FROM_SENDER_MISMATCH",
                category="identity",
                severity="LOW",
                description="From and Sender addresses differ.",
                evidence={
                    "from": from_addr.email,
                    "sender": sender.email,
                },
                related_headers=["From", "Sender"],
            )
        )

    # 6. Missing Return-Path
    if return_path is None or not return_path.email:
        findings.append(
            HeaderForensicFinding(
                code="MISSING_RETURN_PATH",
                category="routing",
                severity="INFO",
                description="Return-Path header is absent or empty.",
                evidence={},
                related_headers=["Return-Path"],
            )
        )

    # 7. Unusual Reply-To
    reply_to_header = parsed_email.get_header("reply-to")
    if reply_to_header is not None:
        # If reply-to is explicitly present but empty or contains multiple distinct addresses
        if not reply_to_header.strip():
            findings.append(
                HeaderForensicFinding(
                    code="UNUSUAL_REPLY_TO",
                    category="identity",
                    severity="LOW",
                    description="Reply-To header is present but empty.",
                    evidence={"reply_to": reply_to_header},
                    related_headers=["Reply-To"],
                )
            )
        elif len(parsed_email.reply_to_addresses) > 1:
            findings.append(
                HeaderForensicFinding(
                    code="UNUSUAL_REPLY_TO",
                    category="identity",
                    severity="LOW",
                    description="Reply-To header specifies multiple addresses.",
                    evidence={
                        "reply_to_addresses": [
                            a.email for a in parsed_email.reply_to_addresses
                        ]
                    },
                    related_headers=["Reply-To"],
                )
            )

    # 8. Missing Date
    date_header = parsed_email.get_header("date")
    if date_header is None:
        findings.append(
            HeaderForensicFinding(
                code="MISSING_DATE",
                category="header_integrity",
                severity="LOW",
                description="Date header is missing.",
                evidence={},
                related_headers=["Date"],
            )
        )

    # 9. Invalid Date
    if date_header is not None and parsed_email.date is None:
        findings.append(
            HeaderForensicFinding(
                code="INVALID_DATE",
                category="header_integrity",
                severity="MEDIUM",
                description="Date header is present but contains an unparseable or invalid date.",
                evidence={"raw_date": date_header},
                related_headers=["Date"],
            )
        )

    # 10. Missing Message-ID
    msg_id = parsed_email.message_id_header
    if not msg_id or not msg_id.strip():
        findings.append(
            HeaderForensicFinding(
                code="MISSING_MESSAGE_ID",
                category="header_integrity",
                severity="LOW",
                description="Message-ID header is missing.",
                evidence={},
                related_headers=["Message-ID"],
            )
        )
    else:
        # 11. Malformed Message-ID
        cleaned_id = msg_id.strip()
        if not _MESSAGE_ID_SYNTAX.match(cleaned_id):
            findings.append(
                HeaderForensicFinding(
                    code="MALFORMED_MESSAGE_ID",
                    category="header_integrity",
                    severity="LOW",
                    description="Message-ID does not conform to standard '<id@host>' format.",
                    evidence={"message_id": msg_id},
                    related_headers=["Message-ID"],
                )
            )

    # 12. Duplicate identity headers
    header_counts: dict[str, int] = {}
    for h in parsed_email.headers:
        lowered = h.name.lower().strip()
        if lowered in _SINGLE_OCCURRENCE_IDENTITY_HEADERS:
            header_counts[lowered] = header_counts.get(lowered, 0) + 1

    for h_name, count in header_counts.items():
        if count > 1:
            findings.append(
                HeaderForensicFinding(
                    code="DUPLICATE_IDENTITY_HEADERS",
                    category="header_integrity",
                    severity="MEDIUM",
                    description=f"Duplicate identity header detected: '{h_name}' appears {count} times.",
                    evidence={"header": h_name, "count": count},
                    related_headers=[h_name.capitalize()],
                )
            )

    # 13. Folded header whitespace
    folded_headers: list[str] = []
    for h in parsed_email.headers:
        # Check if original value had multiline whitespace folding (\r\n or \n with whitespace)
        if re.search(r"\r?\n[ \t]+", h.original_value):
            folded_headers.append(h.name)

    if folded_headers:
        findings.append(
            HeaderForensicFinding(
                code="FOLDED_HEADER_WHITESPACE",
                category="header_integrity",
                severity="INFO",
                description="One or more headers contain folded whitespace normalized during parsing.",
                evidence={"headers_with_folding": folded_headers},
                related_headers=folded_headers,
            )
        )

    has_anomalies = any(f.severity in ("LOW", "MEDIUM") for f in findings)

    return HeaderForensicResult(
        findings=findings,
        total_findings=len(findings),
        has_anomalies=has_anomalies,
    )
