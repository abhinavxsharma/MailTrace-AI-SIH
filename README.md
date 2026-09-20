# MAILTRACE AI — Pre-Open Email Threat Detection & Forensic Intelligence Platform

[![Backend Test Suite](https://img.shields.io/badge/Backend%20Tests-431%20Passed-brightgreen.svg)](#testing)
[![TypeScript](https://img.shields.io/badge/TypeScript-0%20Errors-blue.svg)](#testing)
[![License](https://img.shields.io/badge/License-Apache%202.0-lightgrey.svg)](#license)
[![Python](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](#technology-stack)
[![React Native](https://img.shields.io/badge/React%20Native-Expo-orange.svg)](#technology-stack)

> **"Protecting users before they interact with suspicious emails, providing explainable remediation, and escalating threats into evidence-based forensic investigation."**

---

## Table of Contents
1. [What is MAILTRACE AI?](#1-what-is-mailtrace-ai)
2. [What Problem Does It Solve?](#2-what-problem-does-it-solve)
3. [Who Is It For?](#3-who-is-it-for)
4. [How Does Pre-Open Protection Work?](#4-how-does-pre-open-protection-work)
5. [What Actions Can Users Take?](#5-what-actions-can-users-take)
6. [How Does Deep Forensic Investigation Work?](#6-how-does-deep-forensic-investigation-work)
7. [What Makes It Different from a Normal Spam Filter?](#7-what-makes-it-different-from-a-normal-spam-filter)
8. [Technology Stack](#8-technology-stack)
9. [Architecture & Ingestion Pipeline](#9-architecture--ingestion-pipeline)
10. [Demonstration & Quickstart](#10-demonstration--quickstart)
11. [Environment Variables](#11-environment-variables)
12. [Privacy & Zero-Trust Security Model](#12-privacy--zero-trust-security-model)
13. [Limitations & Defensible Attribution](#13-limitations--defensible-attribution)
14. [Documentation Sitemap](#14-documentation-sitemap)

---

## 1. What is MAILTRACE AI?

**MAILTRACE AI** is an advanced email security and digital forensic intelligence platform designed to protect individuals and organizations against sophisticated email threats including Business Email Compromise (BEC), executive display-name impersonation, credential harvesting, and domain spoofing.

Unlike traditional email gateways that scan emails passively upon receipt or rely on generic blacklists, MAILTRACE AI introduces an automated **Pre-Open Security Layer**. Arriving messages are analyzed in memory in under 50 milliseconds before end users open them. High-risk messages produce real-time threat alerts with explainable reasons, enable one-click remediation directly within Gmail, and seamlessly escalate into an evidence-dense Security Operations Center (SOC) forensic workstation.

---

## 2. What Problem Does It Solve?

Email remains the primary attack vector for enterprise breaches and financial fraud:
- **Zero-Day & Targeted Lures**: Attackers craft convincing AI-generated text, lookalike domains, and urgent executive requests that evade static signature filters.
- **The "Open-First" Dilemma**: In conventional email clients, users must open an email to see its contents or warning banners, exposing them to hidden tracking pixels, malicious redirect scripts, and social engineering lures.
- **Lack of Explainability**: Legacy spam filters mark emails as spam without explaining *why*, leaving users confused and likely to whitelist dangerous messages.
- **Disconnection from SOC Investigation**: When a user is targeted by a sophisticated BEC lure, there is no bridge to escalate the incident into an actionable forensic case with infrastructure attribution and campaign clustering.

MAILTRACE AI resolves this by intercepting messages before opening, explaining indicators in plain language, empowering instant remediation, and correlating threats across attack campaigns.

---

## 3. Who Is It For?

MAILTRACE AI provides a dual-persona interface:

| Target Audience | Interface | Purpose |
|---|---|---|
| **End Users / Executives** | **Mobile-First Security Inbox** | Simple, clear decision-making: *"Is this email safe, and what should I do?"* One-click Report Spam, Block Sender, and Move to Trash. |
| **SOC Analysts / Incident Responders** | **Desktop Forensic Workstation** | Evidence-based attribution: *"What infrastructure sent this, what headers failed, what model probabilities fired, and is this linked to an active campaign?"* |

---

## 4. How Does Pre-Open Protection Work?

MAILTRACE AI connects to Gmail via authenticated Google OAuth 2.0 with near-real-time push notifications (via Google Cloud Pub/Sub) and fallback history synchronization.

When a new message arrives:
1. **Lightweight Header Triage**: Extracts sender, display name, `Reply-To`, `Return-Path`, and SPF/DKIM/DMARC status in memory.
2. **Identity Verification**: Cross-references sender display names against actual header domains to identify spoofing and executive role impersonation.
3. **AI Sequence Classification**: Runs a fine-tuned DistilBERT transformer model (`dataset3_v1.0.0`) in-memory to detect deceptive lures.
4. **Risk Synthesis (< 50ms)**: The Risk Engine aggregates findings into an integer score (0–100) and risk tier (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
5. **Zero Disk Storage**: The message content is never written to disk as a `.eml` file.
6. **Pre-Open Alert**: If flagged as high risk, a prominent alert banner is displayed to the user before they interact with the raw message.

---

## 5. What Actions Can Users Take?

From the Pre-Open Security Preview, users have immediate, authenticated protective control directly executed in their Gmail account:

- **Report Spam**: Adds the `SPAM` label and removes `INBOX` via Gmail API (`users.messages.modify`).
- **Block Sender**: Idempotently creates a Gmail filter via Gmail Settings API (`users.settings.filters.create`) routing future messages from the sender to Trash.
- **Move to Trash**: Safely relocates the email to Gmail Trash (`users.messages.trash`) without irreversible permanent deletion.
- **Investigate Deep Forensics**: One-click escalation that launches the deep forensic pipeline and creates a tracked incident case.

All actions are user-confirmed and operate with clear, real-time feedback.

---

## 6. How Does Deep Forensic Investigation Work?

When escalated by an analyst or user, MAILTRACE invokes the deep `AnalysisPipeline`, conducting multi-stage forensic analysis:

1. **RFC 822 MIME Breakdown**: Full header dissection, attachment SHA-256 fingerprinting, and Received hop chain parsing.
2. **Cryptographic Authentication**: Cryptographic verification of DKIM digital signatures against public DNS records.
3. **Source Infrastructure Attribution**: Extracts originating IPs, queries reverse DNS, retrieves ASN network ownership, and queries RDAP domain registration records.
4. **Approximate Geolocation**: Resolves originating IP addresses to approximate geographical locations.
5. **Campaign Correlation Graph**: Compares threat indicators against historical incidents, identifying shared infrastructure, common dropboxes, and attack clusters.
6. **Forensic Dossier Generation**: Generates exportable, court-ready forensic reports with persistent case linkage (`alert_id` ➔ `message_id` ➔ `case_id`).

---

## 7. What Makes It Different from a Normal Spam Filter?

| Feature | Standard Spam Filter | MAILTRACE AI |
|---|---|---|
| **Inspection Timing** | Passive, post-delivery | **Pre-Open Security Preview** before user interaction |
| **Privacy Invariants** | Often logs raw text to databases | **Strictly in-memory** (<50ms fast path, zero `.eml` on disk) |
| **Explainability** | Opaque spam score | **Plain-English explainable reasons** & indicator tags |
| **Remediation Actions** | User must manually flag in webmail | **One-click authenticated Gmail actions** (Spam/Block/Trash) |
| **SOC Escalation** | None (siloed in spam folder) | **Seamless transition** to multi-stage forensic workstation |
| **Campaign Intelligence**| Isolated per email | **Threat correlation graph** clustering related infrastructure |
| **Attribution Ethics** | May make false claims | **Evidence-based attribution** (Approx. IP, observed infra) |

---

## 8. Technology Stack

### Backend
- **Framework**: Python 3.11+ / FastAPI (Asynchronous REST API)
- **Database**: SQLite (local development) / PostgreSQL (production ready) via SQLAlchemy 2.0 ORM
- **Machine Learning**: PyTorch, Hugging Face Transformers (`dataset3_v1.0.0` DistilBERT)
- **Email & Forensics**: Standard RFC 822/5322 parsers, `dnspython`, `authres`, `ipwhois`
- **Testing**: `pytest`, `unittest.IsolatedAsyncioTestCase`, `httpx` (431 automated tests)

### Frontend
- **Framework**: React Native / Expo (Unified Web & Mobile architecture)
- **Platforms**: Mobile (Android/iOS) + Responsive Desktop Web Workstation
- **Styling**: Native StyleSheet design system with glassmorphic cards and dynamic security badges
- **Language**: TypeScript (0 compile errors)

---

## 9. Architecture & Ingestion Pipeline

```
Gmail Mailbox
      ↓
Google Cloud Pub/Sub Webhook (or on-demand sync)
      ↓
POST /api/webhooks/google/gmail (extracts trigger historyId)
      ↓
sync_gmail_mailbox (Fast background worker)
      ↓
Safe Watch Renewal Check (renew_mailbox_watch_if_needed)
      ↓
history.list (discovers newly added messages since last historyId)
      ↓
Deduplication Check (Unique constraint on [mailbox_id, message_id])
      ↓
Fetch message metadata & parse NormalizedEmail in memory
      ↓
Fast Pre-Open Threat Scan (<50ms DistilBERT + Heuristics)
      ↓
Persist SecurityAlert & Link Baseline Case
      ↓
Advance Mailbox historyId
      ↓
Frontend Discovers Alert (Near-real-time poll / push)
      ↓
Prominent Threat Alert Banner ("🚨 CRITICAL THREAT INTERCEPTED")
      ↓ [ Review ]
Pre-Open Security Preview Modal
      ├── [ Report Spam / Block Sender / Move to Trash ]
      └── [ Investigate Deep Forensics ]
               ↓
          POST /api/mailboxes/{id}/messages/{msg_id}/analyze
               ↓
          AnalysisPipeline (Deep forensics, RDAP, GeoIP, Correlation)
               ↓
          SOC Workstation Dashboard & Threat Graph
```

---

## 10. Demonstration & Quickstart

### Prerequisites
- Python 3.11+
- Node.js 18+ and npm
- Git

### Backend Setup
```bash
# 1. Navigate to backend directory
cd backend

# 2. Activate virtual environment
source ../.venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Start the FastAPI server
uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```
Verify: `curl -s http://127.0.0.1:8000/api/health` returns `{"status":"ok"}`.

### Frontend Setup
```bash
# 1. Navigate to frontend directory
cd frontend

# 2. Install dependencies
npm install

# 3. Run Web Preview server (serves on http://127.0.0.1:5173)
npm run web:preview

# OR run live Expo development server:
npm run web
```

### Live Security Evaluation Flow
1. Open `http://127.0.0.1:5173` (or connect via mobile client).
2. Connect your Gmail mailbox via Google OAuth (`Connect Gmail Account`).
3. Send a controlled evaluation email to the connected account.
4. Observe the automatic **Threat Alert Banner** appear in real-time (<200ms).
5. Click **`[ 🛡 Review Security Preview ]`** to open the in-memory Pre-Open Security Check.
6. Execute immediate remediation (**Report Spam**, **Block Sender**, or **Move to Trash**).
7. Click **`[ Investigate Deep Forensics ]`** to explore the complete SOC Workstation.

For live Gmail testing and SIH pitch instructions, consult [SIH Demonstration & Evaluation Guide](docs/sih-demo-guide.md).

---

## 11. Environment Variables

Copy `.env.example` to `.env` in the repository root:

```ini
# Application Identity & Security
APP_NAME="MAILTRACE AI"
APP_VERSION="0.1.0"
APP_ENV="development"
DEBUG=false
SECRET_KEY="your-random-secret-key"

# Database Configuration
DATABASE_URL="sqlite:///./mailtrace.db"

# Machine Learning Models Directory
MODEL_PATH="ml/models/dataset3_v1.0.0"

# Frontend API URL (for mobile LAN testing, replace with your workstation's LAN IP)
EXPO_PUBLIC_API_URL="http://127.0.0.1:8000"

# Google Cloud OAuth 2.0 Credentials
GOOGLE_CLIENT_ID="your-client-id.apps.googleusercontent.com"
GOOGLE_CLIENT_SECRET="your-client-secret"
GOOGLE_REDIRECT_URI="http://127.0.0.1:8000/api/auth/google/callback"
GOOGLE_OAUTH_SCOPES="https://www.googleapis.com/auth/gmail.readonly,https://www.googleapis.com/auth/gmail.modify,https://www.googleapis.com/auth/gmail.settings.basic"

# Google Cloud Pub/Sub Topic (Optional for push notifications)
GOOGLE_PUBSUB_TOPIC="projects/your-project/topics/gmail-notifications"
```

---

## 12. Privacy & Zero-Trust Security Model

MAILTRACE AI enforces strict privacy and security invariants:
- **Zero Raw `.eml` Disk Persistence**: Emails evaluated during automatic monitoring and pre-scan are parsed entirely in memory. No temporary or unencrypted `.eml` files are written to disk.
- **Zero Token Leakage**: OAuth access tokens, refresh tokens, and client secrets are strictly redacted and never emitted to application logs or API responses.
- **No Raw Email Bodies in Alert Database**: Alert records store only sanitized sender headers, subjects, risk metrics, explainable reasons, and indicator tags.
- **User-in-the-Loop Remediation**: Automatic monitoring never deletes or blocks emails autonomously. Destructive operations require explicit user consent.

---

## 13. Limitations & Defensible Attribution

- **Near-Real-Time, Not Instantaneous**: Push notification delivery depends on Google Cloud Pub/Sub and network latency. Bounded fallback synchronization is maintained for reliability.
- **Defensible Threat Attribution**: MAILTRACE AI attributes threats to **observed infrastructure** (originating mail servers, ASN networks, domain registrars) and calculates **approximate IP geolocation**. It does not make unprovable claims regarding the exact human identity or physical location of an attacker.
- **Authentication Alignment**: Passing SPF or DKIM indicates domain authorization; it is not treated as absolute proof that the content is benign (e.g. compromised legitimate accounts).
- **Latency Scope**: Measured alert delivery latency (<15ms) reflects warm local/LAN network SSE dispatch; physical mobile device latency may vary depending on device WiFi, power management, and radio state.
- **Verification Distinctions**:
  - **Local Web Build Verification**: `npx expo export --platform web` statically compiles and bundles 145 TypeScript modules (482 KB) verifying asset pipelines, but is distinct from full automated multi-browser driver testing.
  - **Gmail OAuth Lifecycle**: Fully implemented and validated via automated HTTP integration tests and mock credentials; real-account end-to-end evaluation requires registered Google Cloud OAuth credentials and verified consent.

---

## 14. Documentation Sitemap

- **[`docs/architecture.md`](docs/architecture.md)** — Comprehensive architecture, data models, and pipeline design.
- **[`docs/user-workflow.md`](docs/user-workflow.md)** — Detailed dual-persona user and SOC analyst workflows.
- **[`docs/sih-demo-guide.md`](docs/sih-demo-guide.md)** — SIH 2-minute judge pitch script and live Gmail demonstration checklist.
- **[`docs/gmail-monitoring-alerting.md`](docs/gmail-monitoring-alerting.md)** — Watch lifecycle, Pub/Sub push, and alerting policies.
- **[`docs/gmail-remediation.md`](docs/gmail-remediation.md)** — Spam reporting, sender blocking, and safe trashing mechanics.
- **[`docs/pre-open-scan.md`](docs/pre-open-scan.md)** — Fast-path in-memory threat scanner implementation.

---

## Testing

```bash
# Backend test suite (447 tests, 100% passing)
cd backend && ../.venv/bin/pytest -q

# Frontend TypeScript check (0 errors)
cd frontend && npx tsc --noEmit

# Frontend production web export (static bundle verification)
cd frontend && npx expo export --platform web
```
