"""
MAILTRACE AI — Pre-Open Email Threat Detection Service.

Provides fast, lightweight, in-memory security preview analysis for Gmail
messages before an end user opens them. Evaluates sender identity, header
consistency, cryptographic authentication, linguistic social engineering lures,
and DistilBERT AI classification without writing any raw content to disk.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from backend.app.core.logging import logger
from backend.app.models.enums import Classification
from backend.app.schemas.analysis import NormalizedEmail
from backend.app.schemas.pre_open import AuthenticationSummary, PreOpenScanResponse
from backend.app.services.intelligence.nlp_entities import extract_entities
from backend.app.services.intelligence.nlp_intent import extract_threat_intents
from backend.app.services.risk.levels import RiskLevel
from backend.app.services.risk.risk_engine import RiskEngine

# Regex heuristics for fast linguistic threat detection
_RE_FINANCIAL = re.compile(
    r"\b(wire\s+transfer|payment\s+instructions?|bank\s+transfer|invoice\s+payment|"
    r"swift\s+code|routing\s+number|remittance\s+advice|payroll\s+update|executive\s+wire)\b",
    re.IGNORECASE,
)

_RE_CREDENTIAL = re.compile(
    r"\b(verify\s+your\s+account|password\s+reset|account\s+suspended|confirm\s+credentials|"
    r"login\s+to\s+restore|unauthorized\s+activity|security\s+alert|sign\s+in\s+to\s+continue|"
    r"update\s+your\s+password|restore\s+your\s+account|credential\s+theft)\b",
    re.IGNORECASE,
)

_RE_URGENCY = re.compile(
    r"\b(urgent|immediately|action\s+required|within\s+24\s+hours?|account\s+will\s+be\s+closed|"
    r"final\s+notice|immediate\s+response|process\s+immediately)\b",
    re.IGNORECASE,
)

_RE_EXEC_ROLE = re.compile(
    r"\b(cfo|ceo|coo|cto|president|director|executive|administrator|admin|it\s+support|helpdesk)\b",
    re.IGNORECASE,
)

_RE_IP_HOST = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


def _extract_auth_summary(
    parsed_email: Any,
    headers_dict: Dict[str, str],
) -> Tuple[AuthenticationSummary, Dict[str, Any]]:
    """Extract SPF, DKIM, and DMARC results from Authentication-Results and verifier."""
    spf_status = "none"
    dkim_status = "none"
    dmarc_status = "none"

    # 1. Primary: Extract authoritative MTA evaluation from Authentication-Results / Received-SPF
    try:
        from forensics.authentication.verifier import parse_authentication_results_header

        auth_res_val = headers_dict.get("authentication-results", "")
        claims = parse_authentication_results_header(auth_res_val)

        if "spf" in claims:
            spf_status = claims["spf"].lower()
        if "dkim" in claims:
            dkim_status = claims["dkim"].lower()
        if "dmarc" in claims:
            dmarc_status = claims["dmarc"].lower()

        # Fallback to Received-SPF header if SPF missing
        if spf_status == "none" and "received-spf" in headers_dict:
            rec_spf = headers_dict["received-spf"].lower()
            if rec_spf.startswith("pass"):
                spf_status = "pass"
            elif rec_spf.startswith("fail"):
                spf_status = "fail"
            elif rec_spf.startswith("softfail"):
                spf_status = "softfail"

    except Exception as exc:
        logger.debug("Failed to parse authentication headers in pre-open scan: %s", exc)



    # Standardize display statuses
    spf_upper = spf_status.upper() if spf_status else "NONE"
    dkim_upper = dkim_status.upper() if dkim_status else "NONE"
    dmarc_upper = dmarc_status.upper() if dmarc_status else "NONE"

    is_authenticated = (dmarc_upper == "PASS") or (spf_upper == "PASS" and dkim_upper == "PASS")

    auth_summary = AuthenticationSummary(
        spf=spf_upper,
        dkim=dkim_upper,
        dmarc=dmarc_upper,
        authenticated=is_authenticated,
    )

    evidence_auth = {
        "spf": spf_status,
        "dkim": dkim_status,
        "dmarc": dmarc_status,
        "authenticated": is_authenticated,
    }

    return auth_summary, evidence_auth


def _extract_identity_indicators(
    parsed_email: Any,
) -> Tuple[Dict[str, Any], List[str], List[str]]:
    """Analyze identity consistency, Reply-To mismatches, and spoofing signals."""
    reasons: List[str] = []
    indicators: List[str] = []

    try:
        from forensics.headers.forensics import analyze_headers

        header_forensics = analyze_headers(parsed_email)
        finding_codes = {f.code for f in header_forensics.findings}

        sender_reply_to_mismatch = (
            "FROM_REPLY_TO_MISMATCH" in finding_codes
            or "SENDER_REPLY_TO_MISMATCH" in finding_codes
            or (
                parsed_email.from_address
                and parsed_email.from_address.email
                and any(
                    r.email and r.email.lower() != parsed_email.from_address.email.lower()
                    for r in parsed_email.reply_to_addresses
                )
            )
        )
        sender_return_path_mismatch = (
            "FROM_RETURN_PATH_MISMATCH" in finding_codes
            or "SENDER_RETURN_PATH_MISMATCH" in finding_codes
            or (
                parsed_email.from_address
                and parsed_email.from_address.domain
                and parsed_email.return_path
                and parsed_email.return_path.domain
                and parsed_email.return_path.domain.lower() != parsed_email.from_address.domain.lower()
            )
        )
        display_name_spoofing = (
            "DISPLAY_NAME_SPOOFING" in finding_codes
            or (
                parsed_email.from_address
                and parsed_email.from_address.display_name
                and bool(_RE_EXEC_ROLE.search(parsed_email.from_address.display_name))
            )
        )
        domain_spoofing = "DOMAIN_SPOOFING" in finding_codes or display_name_spoofing

    except Exception as exc:
        logger.debug("Fast header forensics error in pre-open scan: %s", exc)
        sender_reply_to_mismatch = False
        sender_return_path_mismatch = False
        domain_spoofing = False
        display_name_spoofing = False
        finding_codes = set()

    # Detect Free Webmail Corporate Impersonation (BEC)
    free_webmail_impersonation = False
    try:
        free_webmail_domains = {"gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com", "protonmail.com", "icloud.com"}
        sender_domain = (parsed_email.from_address.domain or "").lower() if (parsed_email and parsed_email.from_address) else ""
        is_free_webmail = sender_domain in free_webmail_domains
        display_or_subject = f"{getattr(parsed_email.from_address, 'display_name', '') or ''} {getattr(parsed_email, 'subject', '') or ''}".lower()
        has_exec_lure = bool(re.search(r"\b(executive|ceo|cfo|wire transfer|invoice|payroll|security team|accounts? dept|account verification|payment instruction)\b", display_or_subject))
        if is_free_webmail and has_exec_lure:
            free_webmail_impersonation = True
            display_name_spoofing = True
            domain_spoofing = True
            reasons.append(f"Executive or corporate financial lure originating from public webmail ({sender_domain})")
            indicators.append("IDENTITY_FREE_WEBMAIL_IMPERSONATION")
    except Exception:
        pass

    # Evidence dictionary for the risk engine
    evidence_identity = {
        "sender_reply_to_mismatch": sender_reply_to_mismatch,
        "sender_return_path_mismatch": sender_return_path_mismatch,
        "domain_spoofing": domain_spoofing,
        "display_name_spoofing": display_name_spoofing,
        "free_webmail_impersonation": free_webmail_impersonation,
        "inconsistent_headers": len(finding_codes) > 0 or sender_reply_to_mismatch or free_webmail_impersonation,
    }

    if sender_reply_to_mismatch:
        reasons.append("Reply-To address mismatch detected: responses will be routed to an alternate address")
        indicators.append("IDENTITY_REPLY_TO_MISMATCH")

    if sender_return_path_mismatch:
        reasons.append("Return-Path envelope domain differs from sender address")
        indicators.append("IDENTITY_RETURN_PATH_MISMATCH")

    if display_name_spoofing and not free_webmail_impersonation:
        reasons.append("Display name impersonation or deceptive identity detected")
        indicators.append("IDENTITY_DISPLAY_NAME_SPOOFING")

    return evidence_identity, reasons, indicators


def _extract_content_indicators(
    subject: str,
    body: str,
    extracted_urls: List[Any],
) -> Tuple[Dict[str, Any], List[str], List[str]]:
    """Evaluate linguistic threat lures and inexpensive URL domain indicators."""
    reasons: List[str] = []
    indicators: List[str] = []

    text_to_scan = f"{subject} {body}"

    # 1. Financial wire/invoice lures
    if _RE_FINANCIAL.search(text_to_scan):
        reasons.append("Financial solicitation detected: message requests wire transfer or invoice payment")
        indicators.append("LURE_FINANCIAL_REQUEST")

    # 2. Credential harvesting lures
    if _RE_CREDENTIAL.search(text_to_scan):
        reasons.append("Credential harvesting lure detected: message prompts login or account verification")
        indicators.append("LURE_CREDENTIAL_HARVESTING")

    # 3. Urgency language
    if _RE_URGENCY.search(text_to_scan):
        reasons.append("High-pressure urgency language detected in subject or body")
        indicators.append("LURE_HIGH_URGENCY")

    has_suspicious_urls = False
    has_suspicious_domain = False
    for u in extracted_urls:
        host = getattr(u, "host", "") or ""
        original_url = getattr(u, "original_url", "") or ""
        # IP address as hostname in URL is a high-risk indicator
        if _RE_IP_HOST.match(host.strip("[]")):
            has_suspicious_urls = True
            has_suspicious_domain = True
            indicators.append("URL_IP_LITERAL_HOST")
            break
        # Phishing keywords in URL path or query
        if any(kw in original_url.lower() for kw in ("/login", "/verify", "/restore", "/signin", "/update-pass", "verify", "secure-account", "login")):
            has_suspicious_urls = True
            has_suspicious_domain = True
            indicators.append("URL_CREDENTIAL_PATH_KEYWORD")
            break

    if has_suspicious_urls:
        reasons.append("Suspicious or deceptive URL detected in email content")

    evidence_url = {
        "suspicious_url": has_suspicious_urls,
        "suspicious_urls_detected": has_suspicious_urls,
        "suspicious_domain": has_suspicious_domain,
        "url_count": len(extracted_urls),
    }

    return evidence_url, reasons, indicators


def _run_ml_classification(parsed_email: Any) -> Optional[Any]:
    """Execute DistilBERT inference on parsed email using the existing model."""
    try:
        from ml.inference.classifier import classify_email

        return classify_email(parsed_email)
    except Exception as exc:
        logger.info("Pre-open scan ML inference unavailable (%s); falling back gracefully", exc)
        return None


def scan_email_pre_open(email: NormalizedEmail) -> PreOpenScanResponse:
    """
    Perform a fast, in-memory pre-open threat scan on a normalized email.

    Args:
        email: NormalizedEmail metadata and content.

    Returns:
        Structured PreOpenScanResponse security preview.
    """
    try:
        from forensics.email_parser.parser import parse_email

        parsed = parse_email(email)
    except Exception as exc:
        logger.warning("Failed to parse email in pre_open_scan: %s", exc)
        parsed = None

    # 1. Extract raw headers dictionary for fast lookup
    headers_dict: Dict[str, str] = {}
    for h in email.headers:
        if isinstance(h, dict):
            headers_dict[h.get("name", "").lower()] = h.get("value", "")
        elif hasattr(h, "name") and hasattr(h, "value"):
            headers_dict[h.name.lower()] = h.value

    # Extract sender display name
    sender_name: Optional[str] = None
    if parsed and parsed.from_address and parsed.from_address.display_name:
        sender_name = parsed.from_address.display_name
    elif "from" in headers_dict:
        from_hdr = headers_dict["from"]
        if "<" in from_hdr:
            sender_name = from_hdr.split("<")[0].strip().strip("\"'")

    # 2. Authentication Summary
    auth_summary, evidence_auth = _extract_auth_summary(parsed, headers_dict)

    # 3. Identity Analysis
    if parsed:
        evidence_identity, id_reasons, id_indicators = _extract_identity_indicators(parsed)
    else:
        evidence_identity, id_reasons, id_indicators = {}, [], []

    # 4. Content & URL Lures
    extracted_urls = parsed.extracted_urls if parsed else []
    evidence_url, content_reasons, content_indicators = _extract_content_indicators(
        subject=email.subject or "",
        body=email.body or "",
        extracted_urls=extracted_urls,
    )

    # 5. NLP Threat Intent & Structured Entity Extraction (Fast Path)
    nlp_intents = extract_threat_intents(
        subject=email.subject or "",
        body=email.body or "",
        sender_display_name=sender_name,
    )
    extracted_entities = extract_entities(
        subject=email.subject or "",
        body=email.body or "",
        sender_name=sender_name,
        sender_email=email.sender,
    )

    # 6. Machine Learning Classification (reusing dataset3_v1.0.0 DistilBERT)
    ml_result = _run_ml_classification(parsed) if parsed else None

    # 7. Calculate Normalized Risk Score
    # Enhance content & identity evidence with NLP determinations
    for item in nlp_intents:
        if item.intent in ("financial_transfer", "payment_diversion", "invoice_fraud"):
            content_indicators.append("LURE_FINANCIAL_REQUEST")
        elif item.intent in ("credential_harvesting", "password_reset_lure", "account_takeover"):
            content_indicators.append("LURE_CREDENTIAL_HARVESTING")
        elif item.intent == "urgency_coercion":
            content_indicators.append("LURE_HIGH_URGENCY")
        elif item.intent == "executive_impersonation":
            evidence_identity["display_name_spoofing"] = True

    evidence: Dict[str, Any] = {
        "ml": {
            "label": ml_result.label,
            "prediction": ml_result.label.lower(),
            "confidence": ml_result.confidence,
            "probabilities": ml_result.probabilities,
        }
        if ml_result
        else {},
        "identity": evidence_identity,
        "authentication": evidence_auth,
        "url_domain": evidence_url,
        "nlp": {
            "intents": [i.model_dump() for i in nlp_intents],
            "entity_count": len(extracted_entities),
        },
        "infrastructure": {},  # Deferred to deep forensic analysis
        "campaign": {},        # Deferred to deep forensic analysis
    }

    risk_engine = RiskEngine()
    risk_assessment = risk_engine.calculate_risk(evidence)
    raw_total_score = risk_assessment["total_score"]
    breakdown = risk_assessment["breakdown"]

    # 8. Calibrate threat score with high-confidence ML and severe NLP behavioral lures
    nlp_risk_boost = 0
    has_financial_lure = any(i.intent in ("financial_transfer", "payment_diversion", "invoice_fraud") for i in nlp_intents) or ("LURE_FINANCIAL_REQUEST" in content_indicators)
    has_credential_lure = any(i.intent in ("credential_harvesting", "password_reset_lure", "account_takeover") for i in nlp_intents) or ("LURE_CREDENTIAL_HARVESTING" in content_indicators)
    has_urgency_lure = any(i.intent == "urgency_coercion" for i in nlp_intents) or ("LURE_HIGH_URGENCY" in content_indicators)
    has_exec_lure = any(i.intent == "executive_impersonation" for i in nlp_intents) or evidence_identity.get("display_name_spoofing") or evidence_identity.get("free_webmail_impersonation")

    if has_financial_lure:
        nlp_risk_boost += 15
    if has_credential_lure:
        nlp_risk_boost += 15
    if has_urgency_lure:
        nlp_risk_boost += 10
    if has_exec_lure:
        nlp_risk_boost += 10

    # Determine Critical / Suspicious / Benign
    has_critical = (
        (ml_result and ml_result.label == "MALICIOUS")
        or raw_total_score >= 70
        or (has_financial_lure and (has_urgency_lure or has_credential_lure))
        or (evidence_identity.get("sender_reply_to_mismatch") and not auth_summary.authenticated)
        or (evidence_identity.get("free_webmail_impersonation") and has_financial_lure)
    )

    has_suspicious = (
        has_critical
        or (ml_result and ml_result.label == "SUSPICIOUS")
        or raw_total_score >= 40
        or not auth_summary.authenticated
        or len(content_indicators) > 0
        or len(id_indicators) > 0
        or len(nlp_intents) > 0
    )

    if has_critical:
        verdict = Classification.MALICIOUS
        recommended_action = (
            "Do not open, click any links, or download attachments. "
            "Flag or report this message as a security threat."
        )
        ml_conf = (ml_result.confidence or 0.8) if (ml_result and ml_result.label == "MALICIOUS") else 0.8
        base_malicious_score = int(65 + ml_conf * 15)  # 77 to 80 base
        total_score = max(raw_total_score + nlp_risk_boost, base_malicious_score)
        if (has_financial_lure or has_credential_lure) and (has_urgency_lure or has_exec_lure):
            total_score = max(total_score, 85)
        risk_level = RiskLevel.CRITICAL if total_score >= 85 else RiskLevel.HIGH
    elif has_suspicious:
        verdict = Classification.SUSPICIOUS
        recommended_action = (
            "Exercise caution before opening. Verify the sender's identity "
            "through an external channel before clicking links or replying."
        )
        total_score = max(raw_total_score + nlp_risk_boost, 45)
        risk_level = RiskLevel.HIGH if total_score >= 70 else RiskLevel.MEDIUM
    else:
        verdict = Classification.BENIGN
        recommended_action = (
            "Standard security checks passed. Verified sender identity and clean content. Safe to preview."
        )
        total_score = min(raw_total_score, 20)
        risk_level = RiskLevel.LOW

    total_score = max(0, min(100, total_score))

    # 9. Aggregate explainable reasons and indicators with SPECIFIC threats first
    specific_threat_reasons: List[str] = []
    all_indicators: List[str] = []

    # Put specific NLP threat intent explanations first
    for intent_item in nlp_intents:
        specific_threat_reasons.append(intent_item.explanation)
        all_indicators.append(f"NLP_INTENT_{intent_item.intent.upper()}")

    # Add identity reasons
    specific_threat_reasons.extend(id_reasons)
    all_indicators.extend(id_indicators)

    # Add content / URL reasons
    specific_threat_reasons.extend(content_reasons)
    all_indicators.extend(content_indicators)

    # Add authentication reasons
    auth_reasons: List[str] = []
    if auth_summary.dmarc in ("FAIL", "REJECT"):
        auth_reasons.append("DMARC authenticity check failed for sender domain")
        all_indicators.append("AUTH_DMARC_FAIL")
    elif auth_summary.spf in ("FAIL", "SOFTFAIL"):
        auth_reasons.append("SPF verification failed for sending mail server")
        all_indicators.append("AUTH_SPF_FAIL")
    elif auth_summary.dkim in ("FAIL", "INVALID"):
        auth_reasons.append("DKIM digital signature failed verification")
        all_indicators.append("AUTH_DKIM_FAIL")

    ai_reasons: List[str] = []
    if ml_result and ml_result.label == "MALICIOUS":
        confidence_pct = (ml_result.confidence or 0.0) * 100
        ai_reasons.append(f"AI sequence model confirmed malicious threat lure ({confidence_pct:.1f}% confidence)")
        all_indicators.append("ML_MALICIOUS_THREAT_DETECTED")
    elif ml_result and ml_result.label == "BENIGN" and total_score <= 39:
        ai_reasons.append("AI threat model evaluated content as benign")

    clean_reasons: List[str] = []
    if auth_summary.authenticated:
        clean_reasons.append("Cryptographic authentication verified (SPF/DKIM/DMARC passed)")
    if not id_indicators and not content_indicators and total_score <= 39:
        clean_reasons.append("Clean threat profile: no identity spoofing, credential lures, or financial fraud detected")

    # Combine: specific threats first, then auth, then AI, then clean confirmation
    if verdict in (Classification.MALICIOUS, Classification.SUSPICIOUS):
        all_reasons = specific_threat_reasons + auth_reasons + ai_reasons + clean_reasons
    else:
        all_reasons = clean_reasons + ai_reasons + specific_threat_reasons + auth_reasons

    # Deduplicate while preserving order
    seen_reasons = set()
    deduped_reasons = []
    for r in all_reasons:
        if r not in seen_reasons:
            seen_reasons.add(r)
            deduped_reasons.append(r)
    all_reasons = deduped_reasons

    confidence = ml_result.confidence if ml_result else None

    # Clean display sender
    clean_sender = email.sender
    if "<" in clean_sender and ">" in clean_sender:
        match = re.search(r"<([^>]+)>", clean_sender)
        if match:
            clean_sender = match.group(1)

    return PreOpenScanResponse(
        message_id=email.provider_message_id,
        thread_id=email.thread_id,
        sender=clean_sender,
        sender_name=sender_name,
        subject=email.subject or "(No Subject)",
        received_at=email.received_at or datetime.now(timezone.utc),
        verdict=verdict,
        risk_score=total_score,
        risk_level=risk_level,
        confidence=confidence,
        reasons=all_reasons,
        indicators=all_indicators,
        authentication_summary=auth_summary,
        recommended_action=recommended_action,
        can_investigate=True,
        nlp_intents=nlp_intents,
        extracted_entities=extracted_entities,
        breakdown=breakdown,
    )
