"""Deterministic scoring functions for risk categories."""

from typing import Any, Dict, Optional


def _clamp(val: int, min_val: int, max_val: int) -> int:
    """Clamp an integer value between minimum and maximum bounds."""
    return max(min_val, min(val, max_val))


def score_ai_threat(evidence: Optional[Dict[str, Any]]) -> int:
    """Calculate AI Threat score (0-25).

    Evaluates ML classification label and confidence.
    - MALICIOUS with high confidence scales up to 25.
    - SUSPICIOUS scales up to 15.
    - BENIGN / CLEAN yields 0.

    Args:
        evidence: Dictionary containing ML inference results.

    Returns:
        Integer score between 0 and 25.
    """
    if not evidence or not isinstance(evidence, dict):
        return 0

    label = str(
        evidence.get("label")
        or evidence.get("prediction")
        or evidence.get("classification")
        or ""
    ).upper().strip()

    raw_conf = evidence.get("confidence") or evidence.get("ai_confidence")
    confidence: Optional[float] = None
    if isinstance(raw_conf, (int, float)) and not isinstance(raw_conf, bool):
        confidence = max(0.0, min(float(raw_conf), 1.0))

    score = 0

    if label in ("MALICIOUS", "PHISHING", "SPAM", "THREAT"):
        if confidence is not None:
            score = round(confidence * 25)
        else:
            score = 15
    elif label == "SUSPICIOUS":
        if confidence is not None:
            score = round(confidence * 15)
        else:
            score = 10
    elif label in ("BENIGN", "CLEAN", "HAM", "LEGITIMATE"):
        score = 0
    else:
        score = 0

    return _clamp(score, 0, 25)


def score_identity(evidence: Optional[Dict[str, Any]]) -> int:
    """Calculate Identity mismatch score (0-20).

    Evaluates sender, reply-to, and return-path header inconsistencies.

    Args:
        evidence: Dictionary containing identity analysis results.

    Returns:
        Integer score between 0 and 20.
    """
    if not evidence or not isinstance(evidence, dict):
        return 0

    score = 0

    if evidence.get("sender_reply_to_mismatch") is True:
        score += 8
    if evidence.get("sender_return_path_mismatch") is True:
        score += 8
    if evidence.get("domain_spoofing") is True or evidence.get("domain_spoofing_detected") is True:
        score += 6
    if evidence.get("display_name_spoofing") is True:
        score += 4
    if evidence.get("inconsistent_headers") is True:
        score += 4

    return _clamp(score, 0, 20)


def score_authentication(evidence: Optional[Dict[str, Any]]) -> int:
    """Calculate Email Authentication score (0-15).

    Evaluates SPF, DKIM, and DMARC verification results.
    Treated as threat evidence, not absolute proof.

    Args:
        evidence: Dictionary containing authentication verification results.

    Returns:
        Integer score between 0 and 15.
    """
    if not evidence or not isinstance(evidence, dict):
        return 0

    score = 0

    dmarc = str(evidence.get("dmarc", "")).upper().strip()
    spf = str(evidence.get("spf", "")).upper().strip()
    dkim = str(evidence.get("dkim", "")).upper().strip()

    # DMARC is the primary domain policy assertion
    if dmarc in ("FAIL", "REJECT", "QUARANTINE"):
        score += 8
    elif dmarc in ("PERMERROR", "TEMPERROR"):
        score += 4

    # SPF alignment and verification
    if spf in ("FAIL", "SOFTFAIL", "PERMERROR"):
        score += 4

    # DKIM signature validation
    if dkim in ("FAIL", "PERMERROR"):
        score += 4

    # If all three are explicit PASS, score is strictly 0
    if dmarc == "PASS" and spf == "PASS" and dkim == "PASS":
        score = 0

    return _clamp(score, 0, 15)


def score_url_domain(evidence: Optional[Dict[str, Any]]) -> int:
    """Calculate URL and Domain risk score (0-15).

    Evaluates presence of suspicious links, domain age, typosquatting, etc.

    Args:
        evidence: Dictionary containing URL and domain findings.

    Returns:
        Integer score between 0 and 15.
    """
    if not evidence or not isinstance(evidence, dict):
        return 0

    score = 0

    if evidence.get("suspicious_domain") is True:
        score += 8
    if evidence.get("suspicious_url") is True:
        score += 6
    if evidence.get("domain_mismatch") is True:
        score += 4
    if evidence.get("failed_domain_validation") is True:
        score += 4
    if evidence.get("punycode_or_homograph") is True:
        score += 5

    return _clamp(score, 0, 15)


def score_infrastructure(evidence: Optional[Dict[str, Any]]) -> int:
    """Calculate Infrastructure risk score (0-15).

    Evaluates originating IP, hosting provider, and routing anomalies.

    Args:
        evidence: Dictionary containing infrastructure indicators.

    Returns:
        Integer score between 0 and 15.
    """
    if not evidence or not isinstance(evidence, dict):
        return 0

    score = 0

    if evidence.get("suspicious_ip") is True:
        score += 8
    if evidence.get("suspicious_hosting") is True or evidence.get("bulletproof_host") is True:
        score += 5
    if evidence.get("suspicious_asn") is True or evidence.get("anonymizer_or_tor") is True:
        score += 5
    if evidence.get("high_risk_country_or_routing") is True:
        score += 3

    return _clamp(score, 0, 15)


def score_campaign(evidence: Optional[Dict[str, Any]]) -> int:
    """Calculate Campaign correlation score (0-10).

    Evaluates potential campaign relationship indicators.

    Args:
        evidence: Dictionary containing correlation and campaign evidence.

    Returns:
        Integer score between 0 and 10.
    """
    if not evidence or not isinstance(evidence, dict):
        return 0

    score = 0

    if evidence.get("potential_campaign") is True or evidence.get("campaign_detected") is True:
        score += 10
    elif evidence.get("cluster_id") is not None and str(evidence.get("cluster_id")).strip() != "":
        score += 5

    if evidence.get("multiple_targets_detected") is True:
        score += 5

    return _clamp(score, 0, 10)
