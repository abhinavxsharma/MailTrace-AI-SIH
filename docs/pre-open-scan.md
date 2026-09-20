# Pre-Open Email Threat Detection Foundation (Chunk 1/5)

## 1. What is Pre-Open Threat Scanning?
Pre-Open Threat Scanning is a proactive email security capability that assesses the safety of an incoming Gmail message **before** the end user opens it in their email client or inbox feed.

Traditional email forensics workflows require an analyst or user to manually open an email and request a full forensic dossier. This introduces risk: opening an email may trigger tracking beacons, execute web payloads, or expose users to deceptive social engineering. Pre-Open Threat Scanning closes this vulnerability by generating a fast, in-memory security preview right at the inbox stage.

---

## 2. Why it Exists & Key Benefits
- **Zero-Day Lure Interception**: Flags urgent wire transfers, credential harvesting pages, and executive impersonation before interaction.
- **Zero Disk Persistence**: The raw `.eml` or RFC 822 payload is ingested and parsed entirely in memory, ensuring complete user privacy and zero data leakage to disk.
- **Explainable Reasons**: Provides non-technical end users with clear, actionable rationale (e.g. *"Reply-To mismatch detected"*, *"DMARC failed"*, *"Credential harvesting lure detected"*) alongside technical indicators.
- **Sub-50ms Latency**: Designed to run at interactive inbox rendering speeds.

---

## 3. Pre-Open Scan vs Deep Forensic Investigation

| Capability | Pre-Open Scan (`POST .../pre-scan`) | Deep Forensic Investigation (`POST .../analyze`) |
|---|---|---|
| **Primary Goal** | Instant inbox preview & safe action guidance | Exhaustive post-incident forensic dossier |
| **Execution Latency** | **< 50ms** (fast in-memory checks) | **1–3s** (multi-stage pipeline) |
| **Parsing** | Header forensics, display name, body snippet | Complete MIME boundary decomposition, attachments |
| **Authentication** | Upstream `Authentication-Results` / `Received-SPF` | Cryptographic RSA-SHA256 & recursive DNS resolution |
| **AI Classification** | DistilBERT `dataset3_v1.0.0` sequence classification | DistilBERT `dataset3_v1.0.0` sequence classification |
| **Threat Intelligence** | Syntax & IP-host URL checks | Live PTR reverse DNS, RDAP WHOIS, MaxMind GeoIP |
| **Campaign Correlation**| Identity indicator checks | Multi-case graph correlation, database clustering |
| **State Persistence** | **Zero DB / Disk persistence** | Persisted `Case`, `AuditEvent`, `Analysis` records |

---

## 4. API Contract

### Request
```http
POST /api/mailboxes/{mailbox_id}/messages/{message_id}/pre-scan
Host: 127.0.0.1:8000
Accept: application/json
```

### Response Schema (`PreOpenScanResponse`)
```json
{
  "message_id": "191e4fbc8a123456",
  "thread_id": "191e4fbc8a123456",
  "sender": "cfo@acme-corp.com",
  "sender_name": "Chief Financial Officer",
  "subject": "URGENT: Executive Wire Transfer Request",
  "received_at": "2026-09-20T01:30:00Z",
  "verdict": "MALICIOUS",
  "risk_score": 65,
  "risk_level": "HIGH",
  "confidence": 0.998,
  "reasons": [
    "AI threat model detected malicious lure (99.8% confidence)",
    "Reply-To address mismatch detected: responses will be routed to an alternate address",
    "Return-Path envelope domain differs from sender address",
    "DMARC authenticity check failed for sender domain",
    "Financial solicitation detected: message requests wire transfer or invoice payment",
    "High-pressure urgency language detected in subject or body"
  ],
  "indicators": [
    "ML_MALICIOUS_THREAT_DETECTED",
    "IDENTITY_REPLY_TO_MISMATCH",
    "IDENTITY_RETURN_PATH_MISMATCH",
    "AUTH_DMARC_FAIL",
    "LURE_FINANCIAL_REQUEST",
    "LURE_HIGH_URGENCY"
  ],
  "authentication_summary": {
    "spf": "FAIL",
    "dkim": "NONE",
    "dmarc": "FAIL",
    "authenticated": false
  },
  "recommended_action": "Do not open, click any links, or download attachments. Flag or report this message as a security threat.",
  "can_investigate": true,
  "breakdown": {
    "ai_threat": 25,
    "identity": 20,
    "authentication": 15,
    "url_domain": 5,
    "infrastructure": 0,
    "campaign": 0
  }
}
```

---

## 5. Security & Privacy
- **In-Memory Streaming**: Operates directly on the OAuth response buffer in memory without writing temporary files to `/tmp` or the repository.
- **Zero Logging of Sensitive Content**: Neither email body text, OAuth refresh tokens, nor private identifiers are logged into application logs.
- **Fail-Safe Fallbacks**: If the local DistilBERT weights are unavailable, the scan gracefully degrades to header forensics and authentication verification without crashing.
