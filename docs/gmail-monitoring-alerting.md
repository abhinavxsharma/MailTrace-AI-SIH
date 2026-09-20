# Automatic Gmail Monitoring, Threat Alerting, and SOC Escalation

This document details the architectural foundation, background lifecycle, threat detection pipeline, and escalation workflow for **Chunk 4: Automatic Gmail Monitoring, Alerting, and SOC Escalation** in MAILTRACE AI.

---

## 1. High-Level Architecture

MAILTRACE AI provides proactive, **near-real-time** email security by monitoring connected Gmail mailboxes and evaluating arriving messages in memory **before** end users open them.

```
┌────────────────────────┐
│  Gmail Mailbox Ingest  │ (Push via Cloud Pub/Sub or Periodic Sync)
└───────────┬────────────┘
            ▼
┌────────────────────────┐
│ Webhook / Sync Service │ (Decodes historyId, checks watch renewal)
└───────────┬────────────┘
            ▼
┌────────────────────────┐
│  History Change Query  │ (list_new_messages_from_history, 404 gap recovery)
└───────────┬────────────┘
            ▼
┌────────────────────────┐
│ Deduplication & Ingest │ (Unique constraint on [mailbox_id, message_id])
└───────────┬────────────┘
            ▼
┌────────────────────────┐
│  Pre-Open Threat Scan  │ (<50ms fast path: DistilBERT + Headers + Auth)
└───────────┬────────────┘
            ▼
┌────────────────────────┐
│ Security Alert Policy  │ (LOW: clean | MED: warning | HIGH/CRITICAL: prominent)
└───────────┬────────────┘
            ▼
┌────────────────────────┐
│  User Security Preview │ (Explainable indicators, reasons, remediation actions)
└───────────┬────────────┘
            ▼
┌────────────────────────┐
│ SOC Deep Investigation │ (Invoked on-demand: GeoIP, RDAP, Graph correlation)
└────────────────────────┘
```

---

## 2. Push Notifications & History Synchronization

### Google Cloud Pub/Sub Push Model
1. Mailboxes register push notifications through `users().watch()` with a designated Google Cloud Pub/Sub topic:
   ```
   projects/<PROJECT_ID>/topics/<TOPIC_ID>
   ```
2. Arriving emails trigger an asynchronous push webhook delivered to `POST /api/webhooks/google/gmail`.
3. The push payload contains only trigger metadata (`emailAddress` and `historyId`), **not** raw email content.
4. The webhook acknowledges the delivery with HTTP `200 OK` and schedules background processing.

### History Retrieval & Bounded Gap Recovery
- Arriving changes are discovered by calling Gmail's `users.history.list` starting from the mailbox's stored `latest_history_id`.
- Gmail history records with `messagesAdded` are collected, deduplicated, and extracted in memory.
- **History Gap / HTTP 404 Fallback**: If Gmail reports that the stored `historyId` is expired or out of date (HTTP 404), the system automatically performs a bounded fallback synchronization (`_bounded_fallback_sync`) querying recent messages and the latest profile `historyId`. This prevents synchronization crashes while maintaining bounded memory limits.

---

## 3. Watch Expiration & Lifecycle Management

Gmail watch subscriptions expire approximately every 7 days. MAILTRACE manages watch health with structured lifecycle logs and safe renewal:

- **Renewal Window**: `renew_mailbox_watch_if_needed(db, mailbox, buffer_minutes=60)` checks if the watch is within 60 minutes of expiration.
- **Duplicate Prevention**: If a watch is active and healthy, renewal requests return the existing watch state without contacting Google APIs unnecessarily.
- **Structured Audit Tags**:
  - `WATCH_CREATED`: Initial registration of a push watch.
  - `WATCH_RENEWED`: Re-registration before expiration.
  - `WATCH_EXPIRED`: Detection of an expired watch.
  - `WATCH_RESTARTED`: Re-activation after expiration.
  - `WATCH_ERROR`: Failed API request or configuration error.

---

## 4. Fast Path vs Deep Path

To ensure lightweight, scalable background operation, MAILTRACE enforces a strict boundary between automated monitoring and in-depth forensic investigation:

| Feature / Step | Fast Pre-Open Path (Automatic) | Deep SOC Forensic Path (On-Demand) |
|---|---|---|
| **Trigger** | Automatic upon message arrival | Analyst / User clicks "Investigate Deep Forensics" |
| **Execution Time** | < 50 milliseconds | 500ms – 2 seconds |
| **Content Processing** | Header analysis, display name, Reply-To triage | Full MIME breakdown, attachment hashing, body extraction |
| **Authentication** | Lightweight SPF, DKIM, DMARC header parsing | Cryptographic DKIM key verification & DNS record retrieval |
| **Machine Learning** | Local DistilBERT classification (`dataset3_v1.0.0`) | DistilBERT + multi-stage behavioral risk weighting |
| **Enrichment** | Fast heuristic URL regex inspection | External GeoIP, RDAP registration lookup, ASN profiling |
| **Correlation** | In-memory message-level indicators | Cross-mailbox campaign clustering & threat graph generation |
| **Artifacts** | `SecurityAlert` record in database | Managed `Case`, `Analysis` record, forensic PDF/JSON export |

---

## 5. Security Alert Policy & Data Model

Incoming messages are classified into 4 standardized risk tiers:

1. **LOW (Risk 0–39)**:
   - **Verdict**: `BENIGN`
   - **User Presentation**: Logged in Security Inbox; positive green confirmation ("✅ All checked messages safe"). Non-intrusive.
2. **MEDIUM (Risk 40–69)**:
   - **Verdict**: `SUSPICIOUS`
   - **User Presentation**: Warning banner and caution badge in inbox; review recommended.
3. **HIGH (Risk 70–89)**:
   - **Verdict**: `MALICIOUS` or `SUSPICIOUS`
   - **User Presentation**: Prominent security alert banner ("🚨 MAILTRACE SECURITY ALERT: HIGH RISK"). Direct buttons to **Review** or **Dismiss**.
4. **CRITICAL (Risk 90–100)**:
   - **Verdict**: `MALICIOUS`
   - **User Presentation**: High-urgency alert banner emphasizing *"Do not open or interact with this email."*

### Database Schema (`SecurityAlert`)
- `alert_id`: Unique human-readable identifier (e.g. `alt_6cf3d1e92a01`).
- `mailbox_id`: Foreign key referencing connected `mailboxes.id`.
- `message_id`: Gmail message ID.
- `thread_id`: Gmail thread ID.
- `case_id`: Foreign key referencing `cases.id` (preserves forensic linkage).
- `sender`, `sender_name`, `subject`: Safe sanitized header strings.
- `verdict`, `risk_score`, `risk_level`, `confidence`: Quantified threat assessment.
- `title`, `summary`: Explainable threat descriptions.
- `reasons`: JSON list of user-facing explanations.
- `indicators`: JSON list of machine-readable threat indicator tags.
- `status`: Enum (`UNREAD`, `READ`, `DISMISSED`, `INVESTIGATING`, `RESOLVED`).
- **Deduplication Constraint**: `UniqueConstraint("mailbox_id", "message_id", name="uq_mailbox_message_alert")`.

---

## 6. Alert REST API

MAILTRACE exposes the following authenticated endpoints for the client:

- `GET /api/mailboxes/{mailbox_id}/alerts`: Retrieves normalized threat alerts, ordered newest first, with optional `status` filter (`UNREAD`, `READ`, `DISMISSED`, etc.).
- `POST /api/mailboxes/{mailbox_id}/alerts/{alert_id}/read`: Marks an alert status as `READ`.
- `POST /api/mailboxes/{mailbox_id}/alerts/{alert_id}/dismiss`: Dismisses an alert (`DISMISSED`).
- `POST /api/mailboxes/{mailbox_id}/sync`: Triggers on-demand history synchronization and pre-open threat scanning.

---

## 7. SOC Escalation Flow

From any security alert:
```
Alert Banner / Card
        ↓ [ Review ]
Pre-Open Security Preview Modal
        ↓
    ├─ [ Report Spam ]         ──> POST /api/mailboxes/{id}/messages/{msg_id}/report-spam
    ├─ [ Block Sender ]        ──> POST /api/mailboxes/{id}/messages/{msg_id}/block-sender
    ├─ [ Move to Trash ]       ──> POST /api/mailboxes/{id}/messages/{msg_id}/delete
    └─ [ Investigate Deep Forensics ]
             ↓
        POST /api/mailboxes/{id}/messages/{msg_id}/analyze
             ↓
        AnalysisPipeline.run() (Deep forensics, RDAP, GeoIP, Correlation)
             ↓
        Updates SecurityAlert: status = "INVESTIGATING", case_id = case.id
             ↓
        Displays Comprehensive SOC Workstation Dossier & Campaign Graph
```

Linkage is strictly preserved across all layers:
`alert_id ──> message_id ──> case_id`

---

## 8. Privacy & Zero-Trust Invariants

1. **Zero Raw `.eml` Writes**: Emails evaluated during automatic monitoring are never written to disk as `.eml` or temporary text files.
2. **Zero Sensitive Token Logging**: OAuth access tokens, refresh tokens, and client secrets are strictly redacted and never outputted in server logs or API payloads.
3. **No Raw Email Body in Alerts**: Alert records persist only sanitized sender, subject, risk metrics, explainable reasons, and indicators. Raw message bodies are not saved to database alert records.
4. **User In The Loop**: Automatic monitoring never performs destructive operations (moving to trash, spam reporting, sender blocking) autonomously. All protective actions require user authorization.
5. **Near-Real-Time Guarantee**: Monitoring operates asynchronously in near-real-time subject to Google Pub/Sub push delivery latency and bounded fallback synchronization.
