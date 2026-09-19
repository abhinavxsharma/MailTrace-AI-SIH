# Gmail Connector — MAILTRACE AI (Chunk 1/7)

## Overview

The Gmail connector is the first layer of the MAILTRACE AI forensic pipeline. It connects to a user's Gmail mailbox via the official Google Gmail API, retrieves messages safely in memory, decodes and normalises them, and produces a typed `NormalizedEmail` object for downstream forensic analysis.

---

## Why the Gmail API (not IMAP/POP3)?

MAILTRACE uses the Gmail REST API instead of IMAP or POP3 for the following reasons:

| Concern | Gmail API | IMAP/POP3 |
|---|---|---|
| Authentication | OAuth 2.0 (no password exposure) | Password or app password required |
| Scope control | Narrow, read-only scope | Full mailbox access |
| Push notifications | Native Pub/Sub watch | Polling only |
| Message addressing | Stable opaque message IDs | Volatile sequence numbers |
| Header/body format | Structured JSON + base64url parts | Raw RFC 2822 MIME download |
| API rate limiting | Managed by Google | Self-managed |
| Privacy control | API-only, no local MIME storage | Full MIME download required |

---

## OAuth 2.0 Flow

### Read-Only Scope

Only the following OAuth scope is requested:

```
https://www.googleapis.com/auth/gmail.readonly
```

This grants MAILTRACE the ability to:
- Read message headers and bodies
- List messages and threads
- Register push notification watches

It **does not** grant the ability to:
- Send, compose, or reply to messages
- Delete or modify messages
- Access Gmail settings

### Development Flow (InstalledAppFlow)

For local development:

1. Download `credentials.json` from the [Google Cloud Console](https://console.cloud.google.com/) (OAuth 2.0 client credentials for a desktop application).
2. Set the environment variable:
   ```
   GOOGLE_OAUTH_CLIENT_SECRETS_FILE=/path/to/credentials.json
   ```
3. On first run, `get_credentials()` opens a browser to complete the OAuth consent screen.
4. After consent, a `token.json` is saved to the path configured by `GOOGLE_OAUTH_TOKEN_FILE` (default: `backend/.secrets/token.json`).
5. Subsequent runs reuse the cached token and auto-refresh it when expired.

### Production Flow (Service Account — Future)

For server deployments, replace `InstalledAppFlow` with a Google service account with domain-wide delegation. The `token.json` cache is not needed in that scenario. See the stub comment in `gmail_auth.py`.

---

## Message ID Flow

```
User's Gmail Inbox
       │
       │ Gmail API: users.messages.list()
       ▼
List of { id, threadId } objects
       │
       │ Gmail API: users.messages.get(id, format='full')
       ▼
Full message payload (JSON, in memory)
       │
       │ message_fetcher._normalize()
       ▼
NormalizedEmail (typed Pydantic model, in memory)
       │
       │ → forensic parser (Chunk 2+)
       ▼
     (future)
```

### Message IDs

Gmail assigns each message a stable, opaque `id` string (e.g. `17d3c8a7b2f1e0c4`). These IDs:
- Survive mailbox moves and label changes.
- Are stable across sessions.
- Are preserved verbatim as `provider_message_id` in `NormalizedEmail`.

### Thread IDs

Gmail groups related messages (replies) into threads via `threadId`. This is preserved as `thread_id` in `NormalizedEmail` for campaign correlation in later chunks.

---

## Gmail API Message Retrieval

Messages are fetched with `format='full'`:

```
users.messages.get(userId='me', id=<message_id>, format='full')
```

This returns a structured JSON response:

```json
{
  "id": "...",
  "threadId": "...",
  "sizeEstimate": 4096,
  "payload": {
    "mimeType": "multipart/alternative",
    "headers": [
      { "name": "From", "value": "sender@example.com" },
      { "name": "Subject", "value": "Hello" },
      { "name": "Date", "value": "Mon, 01 Jan 2024 10:00:00 +0000" }
    ],
    "parts": [
      {
        "mimeType": "text/plain",
        "body": { "data": "<base64url encoded body>" }
      },
      {
        "mimeType": "text/html",
        "body": { "data": "<base64url encoded html>" }
      }
    ]
  }
}
```

Body parts use the URL-safe variant of Base64 (`-` and `_` instead of `+` and `/`) without padding characters. The connector decodes these **in memory** using Python's `base64.urlsafe_b64decode`.

> [!IMPORTANT]
> `format='raw'` is **explicitly blocked** in `GmailClient.get_message()`. The raw format returns the complete RFC 2822 MIME message. MAILTRACE never requests or stores raw MIME content.

---

## In-Memory Processing — No .eml Downloads

> [!CAUTION]
> MAILTRACE never downloads emails to disk. No `.eml` files, no raw MIME files, no temporary message archives are created.

The processing pipeline is:

1. **API call** — `GmailClient.get_message()` returns a Python `dict` in memory.
2. **Header extraction** — headers are normalised into a `dict[str, str]` in memory.
3. **Body decoding** — `base64url` body parts are decoded to strings in memory.
4. **MIME tree walk** — `_collect_parts()` recursively traverses multipart structures in memory.
5. **Model construction** — a `NormalizedEmail` Pydantic model is returned.

At no point is `tempfile`, `open(..., 'w')`, or any file I/O called on message content.

The test suite includes an **explicit privacy sentinel test** (`TestPrivacyNoDiskWrites`) that:
- Asserts no `.eml` or `.mime` files are created in any temp directory.
- Verifies `tempfile` is not imported by `message_fetcher.py`.
- Patches `builtins.open` and asserts it is never called with write mode on sensitive paths.

---

## Mailbox Watch (Push Notifications)

### Concept

Instead of polling `list_recent_messages()` on a timer, Gmail supports **push notifications** via Google Cloud Pub/Sub. When a new message arrives, Gmail publishes a notification to a configured Pub/Sub topic. The backend subscribes to the topic and processes new messages in near real-time.

### Pub/Sub Setup (Required Before Using `start_watch()`)

1. Create a Google Cloud project and enable:
   - Gmail API
   - Cloud Pub/Sub API
2. Create a Pub/Sub topic.
3. Grant the Gmail push service account `gmail-api-push@system.gserviceaccount.com` the `roles/pubsub.publisher` IAM role on the topic.
4. Set environment variables:
   ```
   GOOGLE_CLOUD_PROJECT=my-gcp-project-id
   GMAIL_PUBSUB_TOPIC=gmail-push-notifications
   ```

### Watch Registration

```python
from app.services.mail.gmail_auth import get_credentials
from app.services.mail.gmail_client import GmailClient
from app.services.mail.gmail_watch import start_watch
from app.core.config import get_settings

settings = get_settings()
creds = get_credentials(settings)
client = GmailClient(credentials=creds)

registration = start_watch(client, settings)
print(registration.history_id)   # starting history ID
print(registration.expiration)   # expiry in milliseconds since epoch
```

### Watch Expiry

Gmail watch registrations expire after approximately **7 days**. The `expiration` field of `WatchRegistration` contains the expiry time. The backend must renew the watch before expiry by calling `start_watch()` again.

> [!NOTE]
> The Pub/Sub **consumer** (which listens for incoming notifications and dispatches them to the forensic pipeline) is not implemented in Chunk 1. It will be part of the watch integration layer in a later chunk.

---

## Credential Handling

| File | Purpose | Committed? |
|---|---|---|
| `credentials.json` | OAuth client secrets from GCP Console | **Never** |
| `backend/.secrets/token.json` | Dev OAuth token cache | **Never** |
| `.env` | Environment variable overrides | **Never** |
| `.env.example` | Template with placeholder variable names only | Yes |

The `.gitignore` includes:

```gitignore
credentials.json
token.json
*.token
*.token.json
backend/.secrets/
.secrets/
```

> [!CAUTION]
> Real credentials must never appear in:
> - Python source files
> - Test files
> - `.env.example`
> - README or documentation
> - Git history

---

## Privacy Model

MAILTRACE operates on a **minimal-footprint** principle:

1. **No email archive** — messages are never saved as files locally.
2. **No raw MIME storage** — the Gmail API structured format is used; raw RFC 2822 MIME is never requested.
3. **In-memory only** — all message decoding and normalisation is performed in RAM.
4. **Metadata persistence only** — only selected normalised forensic metadata (headers, sender, subject, routing info) is later persisted by the backend database layer. The message body is not persisted by default.
5. **OAuth read-only** — no write access to the mailbox is ever requested.
6. **Credentials gitignored** — OAuth secrets and tokens are kept out of version control.

---

## Handoff to the Forensic Parser (Chunk 2)

The Gmail connector produces a `NormalizedEmail` at the architectural boundary:

```python
from app.services.mail.models import NormalizedEmail

# Chunk 1 produces this:
email: NormalizedEmail = fetch_and_normalize(client, message_id)

# Chunk 2 will consume it:
forensic_result = analyze(email)  # Not implemented in Chunk 1
```

`NormalizedEmail` fields available to Chunk 2:

| Field | Description |
|---|---|
| `provider` | `"gmail"` |
| `provider_message_id` | Opaque Gmail message ID |
| `thread_id` | Gmail thread ID |
| `sender` | From header (raw RFC 5322 string) |
| `recipients` | Flattened To/Cc/Bcc address list |
| `subject` | Decoded Subject header |
| `body_text` | Decoded text/plain body (or None) |
| `body_html` | Decoded text/html body (or None) |
| `headers` | All headers, lowercased, as dict |
| `received_at` | UTC datetime parsed from Date header |
| `raw_size_bytes` | API-reported size estimate (not raw content) |

Chunk 2 (forensic parser) will use `headers`, `sender`, `received_at`, and `body_text` / `body_html` for authentication checking, IP tracing, and content analysis.

---

## Module Reference

| Module | Responsibility |
|---|---|
| `app.core.config` | `Settings` — reads all configuration from env |
| `app.core.logging` | `get_logger(name)` — JSON-formatted structured logger |
| `app.services.mail.models` | `NormalizedEmail` — typed output model |
| `app.services.mail.gmail_auth` | `get_credentials()` — OAuth 2.0 credential management |
| `app.services.mail.gmail_client` | `GmailClient` — typed Gmail API wrapper |
| `app.services.mail.gmail_watch` | `start_watch()` / `stop_watch()` — push notification registration |
| `app.services.mail.message_fetcher` | `fetch_and_normalize()` — in-memory pipeline |

---

## Environment Variable Reference

| Variable | Required | Default | Description |
|---|---|---|---|
| `GOOGLE_OAUTH_CLIENT_SECRETS_FILE` | Yes (dev) | `credentials.json` | Path to OAuth client secrets JSON |
| `GOOGLE_OAUTH_TOKEN_FILE` | No | `backend/.secrets/token.json` | Dev token cache path |
| `GOOGLE_CLOUD_PROJECT` | Yes (watch) | `""` | GCP project ID for Pub/Sub |
| `GMAIL_PUBSUB_TOPIC` | Yes (watch) | `""` | Pub/Sub topic name |
| `LOG_LEVEL` | No | `INFO` | Log level (DEBUG, INFO, WARNING, ERROR) |
