# MAILTRACE AI — User & Analyst Workflow Guide

MAILTRACE AI explicitly separates the **End-User Protection Experience** from the **SOC Analyst Forensic Experience**, ensuring both non-technical users and forensic investigators receive appropriate, actionable interfaces.

---

## Persona 1: The End-User Protection Workflow

### Core Purpose
**"Is this email safe, and what protective action should I take before opening it?"**

Non-technical users should never be forced to decipher raw Received headers, DKIM RSA keys, or ASN registration records. Instead, MAILTRACE protects them before they interact with potential lures.

```
Incoming Email
      ↓ (Near-Real-Time Automated Threat Check)
Security Inbox / Alert Banner
      ↓ [ Review Security Preview ]
Pre-Open Security Preview Modal
      ├─► [ Report Spam ] ──────► Moved to Gmail Spam folder
      ├─► [ Block Sender ] ─────► Future emails routed to Trash
      ├─► [ Move to Trash ] ────► Safe Gmail Trash folder
      └─► [ Investigate ] ──────► Escalates to Forensic Workstation
```

### Key Capabilities

1. **Near-Real-Time Threat Alerts**:
   - When an email with **HIGH** or **CRITICAL** risk arrives, a prominent red/crimson alert banner appears above the inbox.
   - Summarizes the threat plainly: *"Executive CFO impersonation with unauthorized wire transfer request detected before opening."*

2. **Pre-Open Security Check**:
   - Clicking **[ Review ]** displays the sanitized security preview.
   - Displays the sender display name, actual sending address, and subject.
   - Highlights explainable reasons in plain language:
     - *"AI threat model detected malicious lure (96% confidence)"*
     - *"Reply-To address does not match the sender's claimed domain"*
     - *"DMARC authenticity check failed for sender domain"*
   - Displays clear risk badge (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).

3. **One-Click Remediation**:
   - **Report Spam**: Reports the message in connected Gmail and removes it from the inbox view.
   - **Block Sender**: Idempotently registers a Gmail filter routing future messages from the sender to Trash.
   - **Move to Trash**: Moves the current message to Gmail Trash without irreversible permanent deletion.
   - Confirmation dialogs protect against accidental clicks with clear descriptions.

---

## Persona 2: The SOC Analyst Forensic Workstation

### Core Purpose
**"What evidence do we have, what infrastructure is associated with it, and is it linked to a wider campaign?"**

For security operations teams, incident response analysts, and forensic investigators, MAILTRACE provides an evidence-dense workstation designed for in-depth attribution.

```
Security Alert Escalation (or Manual .eml Upload)
      ↓
SOC Workstation Dashboard
      ├─► Overview & Risk Synthesis (6 category breakdown bars)
      ├─► Header Forensics (Full Received hop trace, Return-Path, Message-ID)
      ├─► Cryptographic Authentication (SPF, DKIM signature verification, DMARC)
      ├─► AI Model Analysis (DistilBERT probabilities & token classification)
      ├─► Infrastructure Intelligence (Reverse DNS, ASN, Approx. Geolocation, RDAP)
      ├─► Campaign Correlation (Cross-case graph & similarity clustering)
      ├─► Chronological Timeline (RFC 822 event trace from origin to delivery)
      └─► Dossier Export (Downloadable forensic case report)
```

### Key Capabilities

1. **6-Category Risk Synthesis**:
   - Breaks down the 0–100 risk score into explainable components:
     - AI Threat Detection (/25)
     - Identity & Impersonation (/20)
     - Cryptographic Authentication (/15)
     - URL & Domain Lures (/15)
     - Source Infrastructure (/15)
     - Campaign Correlation (/10)

2. **Header & Authentication Forensics**:
   - Complete RFC 822 header inspector.
   - Cryptographic verification of DKIM digital signatures against public DNS records.
   - SPF and DMARC alignment validation.

3. **Source Infrastructure & Attribution**:
   - Originating IP extraction from Received hop chains.
   - Reverse DNS hostnames and ASN network ownership.
   - **Approximate IP Geolocation** (defensible country/city attribution).
   - Domain age, registrar, and RDAP registration metadata.

4. **Campaign Correlation & Threat Graph**:
   - Cross-analyzes incoming messages against historical cases.
   - Visualizes shared attack infrastructure (shared mail relays, phishing domains, reply-to dropboxes).
   - Interactive zoomable node-link relationship graph.

5. **Chronological Forensics Timeline**:
   - Traces the complete lifecycle of the message from server dispatch to mailbox arrival with microsecond precision.

6. **Forensic Dossier Generation**:
   - One-click export of a comprehensive, court-ready forensic report including case ID, evidence hashes, and analyst audit trail.
