# MAILTRACE AI — Comprehensive System Architecture

## 1. System Overview

MAILTRACE AI is an end-to-end email threat detection, remediation, and forensic intelligence platform. It bridges the gap between passive user vulnerability and specialized security operations center (SOC) investigation by operating on two distinct execution tiers:

1. **Fast-Path Pre-Open Protection (< 50 ms)**: Evaluates incoming messages in memory before an end user opens or interacts with them, producing actionable threat alerts and safe security previews.
2. **Deep-Path Forensic Investigation (On-Demand)**: Performs comprehensive multi-stage digital forensics, header parsing, cryptographic verification, RDAP/GeoIP enrichment, campaign correlation, and dossier generation when escalated.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              MAILTRACE AI PLATFORM                          │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
            ┌──────────────────────────┴──────────────────────────┐
            ▼                                                     ▼
┌───────────────────────────────┐             ┌───────────────────────────────┐
│     TIER 1: FAST PRE-OPEN     │             │    TIER 2: DEEP FORENSICS     │
│   (Automatic Monitoring / UX) │             │    (SOC Analyst Workstation)  │
├───────────────────────────────┤             ├───────────────────────────────┤
│ • Gmail Push (Pub/Sub) / Sync │             │ • Case & Analysis Management  │
│ • History Change Discovery    │             │ • RFC 822 MIME Breakdown      │
│ • Lightweight Headers & Auth  │             │ • Cryptographic DKIM Verify   │
│ • DistilBERT ML Classifier    │             │ • External RDAP / Whois       │
│ • Alert Policy (Low-Critical) │             │ • Approx. IP Geolocation      │
│ • Remediation (Trash/Spam/Blk)│             │ • Threat Campaign Clustering  │
│ • Zero Disk .eml Persistence  │             │ • Interactive Graph & Timeline│
└───────────────────────────────┘             └───────────────────────────────┘
```

---

## 2. Ingestion & Mailbox Integration

### 2.1 Google OAuth 2.0 Integration
MAILTRACE integrates with user mailboxes using least-privilege Google OAuth 2.0 scopes:
- `https://www.googleapis.com/auth/gmail.readonly`: Read metadata and message content in memory.
- `https://www.googleapis.com/auth/gmail.modify`: Report spam and move messages to Gmail Trash.
- `https://www.googleapis.com/auth/gmail.settings.basic`: Create filters to block malicious senders.

Credentials are encrypted and stored via `TokenStore`. In accordance with zero-trust privacy invariants, credentials, access tokens, and refresh tokens are strictly redacted and never logged.

### 2.2 Push Notifications & History Synchronization
- **Primary Mode**: Gmail push notifications delivered via Google Cloud Pub/Sub to `POST /api/webhooks/google/gmail`.
- **Payload Guarantee**: Push payloads contain only trigger metadata (`emailAddress`, `historyId`) — never raw email bodies.
- **History Change Discovery**: `list_new_messages_from_history` queries Gmail `users.history.list` from the mailbox's stored `latest_history_id`.
- **HTTP 404 Recovery**: If Gmail reports that a stored history ID has expired (HTTP 404), MAILTRACE executes `_bounded_fallback_sync` to re-baseline with recent messages without bulk mailbox downloading.
- **Fallback Mode**: For environments without Cloud Pub/Sub, on-demand synchronization (`POST /api/mailboxes/{id}/sync`) queries history changes safely.

### 2.3 Watch Lifecycle Management
Gmail watch registrations expire every 7 days. `watcher.py` manages renewal:
- `renew_mailbox_watch_if_needed(db, mailbox, buffer_minutes=60)` checks watch expiration.
- **Duplicate Prevention**: If a watch is active (> 60 minutes remaining), it returns the active watch state without calling Google APIs.
- Emits structured audit events: `WATCH_CREATED`, `WATCH_RENEWED`, `WATCH_EXPIRED`, `WATCH_RESTARTED`, `WATCH_ERROR`.

---

## 3. Threat Detection Pipeline

### 3.1 Fast-Path Pre-Open Threat Scan (`pre_open_scan.py`)
Executed automatically on new arrivals. Designed to complete in < 50ms:
1. **Header Extraction**: Parses `From`, `To`, `Subject`, `Reply-To`, `Return-Path`, and `Authentication-Results`.
2. **Identity Verification**: Flags display name spoofing, executive role impersonation, and `Reply-To` vs `From` domain mismatches.
3. **Cryptographic Authentication**: Lightweight triage of SPF, DKIM, and DMARC alignment status.
4. **Linguistic Lure Heuristics**: Detects financial wire transfer requests, urgency cues, and credential reset lures.
5. **AI Threat Model**: In-memory sequence classification using fine-tuned DistilBERT (`dataset3_v1.0.0`).
6. **Risk Engine**: Normalizes evidence into a 0–100 integer score and assigns a risk tier: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`.

### 3.2 Deep-Path Forensic Analysis (`AnalysisPipeline`)
Triggered when an analyst or user escalates via `POST /api/mailboxes/{id}/messages/{msg_id}/analyze`:
1. **Stage 1 (Forensics)**: Full RFC 822/5322 MIME extraction, attachment SHA-256 hashing, Received hop chain trace.
2. **Stage 2 (Authentication)**: Cryptographic signature verification against public DNS DKIM keys.
3. **Stage 3 (Machine Learning)**: DistilBERT inference with detailed class probability distributions.
4. **Stage 4 (Intelligence)**: Originating IP extraction, reverse DNS resolution, ASN lookup, RDAP registrar query, and approximate GeoIP.
5. **Stage 5 (Correlation)**: Cross-case similarity clustering, campaign graph generation, and chronological threat timeline reconstruction.
6. **Stage 6 (Risk Synthesis)**: Weighted risk calculation across all six dimensions.

---

## 4. Alert Policy & Deduplication

### 4.1 Risk Thresholds & Policy Actions
| Risk Tier | Score Range | Default Verdict | User Experience | Permitted Actions |
|---|---|---|---|---|
| **LOW** | 0 – 39 | `BENIGN` | Green clean badge in Security Inbox | Review, Investigate |
| **MEDIUM** | 40 – 69 | `SUSPICIOUS` | Cautionary amber warning in Inbox | Review, Report, Block, Trash, Investigate |
| **HIGH** | 70 – 89 | `MALICIOUS` | High-visibility red alert banner | Review, Report, Block, Trash, Investigate |
| **CRITICAL** | 90 – 100 | `MALICIOUS` | Urgent banner ("Do not open or interact") | Review, Report, Block, Trash, Investigate |

### 4.2 Idempotency & Deduplication
- Database constraint: `UniqueConstraint("mailbox_id", "message_id", name="uq_mailbox_message_alert")`.
- `sync_gmail_mailbox` validates existing records before scanning, preventing duplicate alert creation during repeated push deliveries.

---

## 5. Remediation Engine

MAILTRACE executes real, authenticated protective actions directly in the connected Gmail account:

1. **Report Spam** (`POST .../report-spam`):
   - Adds Gmail `SPAM` label and removes `INBOX` label via `users.messages.modify`.
2. **Move to Trash** (`POST .../delete`):
   - Invokes `users.messages.trash` moving the item safely to Gmail Trash.
   - Non-destructive: avoids permanent irreversible purge (`messages.delete`).
3. **Block Sender** (`POST .../block-sender`):
   - Parses the canonical sender address using `email.utils.parseaddr`.
   - Checks existing user filters via `users.settings.filters.list` to prevent duplicates.
   - Creates a rule via `users.settings.filters.create` directing future mail from that sender to Trash.

---

## 6. End-to-End Case & Linkage Architecture

```
SecurityAlert (alt_xxx)
      │
      ▼ [Foreign Key: alert.case_id]
Case (case_xxx)
      │
      ├─► Analysis Record (Full 6-stage evidence snapshot)
      ├─► Audit Events (Audit trail of detections, reviews, remediations)
      └─► Mailbox (Associated connected account)
```
When deep forensics is requested, the system preserves the persistent linkage:
`alert_id ──> message_id ──> case_id`
Updating `alert.status = AlertStatus.INVESTIGATING`.

---

## 7. Security, Privacy, and Defensibility Invariants

1. **Zero Raw `.eml` Disk Writes**: All processing occurs strictly in memory. Verified across the test suite.
2. **Zero Sensitive Token Logging**: OAuth tokens and client secrets are never logged.
3. **No Raw Email Bodies in Alert Database**: Stores only normalized explainable metadata and risk indicators.
4. **User-in-the-Loop Remediation**: Destructive actions are never automated; explicit confirmation is required.
5. **Defensible Attribution**: Source IP locations are explicitly designated as *approximate*. MAILTRACE attributes threats to *observed infrastructure* rather than unprovable individual actors.
