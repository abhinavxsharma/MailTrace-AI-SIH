# MAILTRACE AI — Gmail Mailbox Integration Guide

This guide details the end-to-end integration between **MAILTRACE AI** and **Google Gmail API** using Google Cloud OAuth 2.0 and Cloud Pub/Sub push notifications.

---

## 1. Architectural Overview & The Zero-.EML Mandate

```
Google Cloud Pub/Sub Push
          │
          ▼
POST /api/webhooks/google/gmail (FastAPI Webhook)
          │ (Quick 200 OK acknowledgment)
          ▼
BackgroundTasks: sync_gmail_mailbox()
          │
          ├─► TokenStore: Resolves & auto-refreshes OAuth Credentials (in-memory)
          ├─► Gmail API: history.list(startHistoryId)
          ├─► Idempotency Check: (provider="gmail", provider_message_id)
          ├─► Gmail API: messages.get(format="full") (in-memory)
          ├─► parse_gmail_message() -> NormalizedEmail (in-memory)
          │
          ▼
AnalysisPipeline.run() (Forensics, Auth, ML, Threat Intel, Correlation, Risk)
          │
          ▼
Database Persistence (Structured Case, Analysis Snapshot, Audit Trail)
```

### Why MAILTRACE AI Does Not Download .EML Files
1. **Security & Data Minimization**: Saving raw `.eml` or email bodies to local disk creates severe data leakage, compliance (GDPR/HIPAA), and disk exhaustion risks.
2. **Real-time SOC Workflow**: SOC analysts monitor connected mailboxes automatically; requiring users to manually export and upload files breaks automated threat detection.
3. **In-Memory Streaming**: Messages are fetched directly from the Gmail API into runtime memory as canonical `NormalizedEmail` objects and inspected across analysis stages. Only structured telemetry, forensic artifacts, and risk scores are persisted.

---

## 2. Google Cloud Console Setup

### Step 1: Create a Google Cloud Project
1. Navigate to the [Google Cloud Console](https://console.cloud.google.com/).
2. Create a new project, e.g., `mailtrace-ai-dev`.

### Step 2: Enable the Gmail API
1. In the navigation menu, go to **APIs & Services > Library**.
2. Search for **Gmail API** and click **Enable**.

### Step 3: Configure the OAuth Consent Screen
1. Go to **APIs & Services > OAuth consent screen**.
2. Choose **External** (or **Internal** if using Google Workspace).
3. Fill in the App Name (`MAILTRACE AI`) and user support email.
4. Under **Scopes**, add the least-privilege read-only scope:
   - `https://www.googleapis.com/auth/gmail.readonly`
5. Add test users (your developer Gmail addresses) under **Test users**.

### Step 4: Create OAuth 2.0 Client Credentials
1. Go to **APIs & Services > Credentials**.
2. Click **Create Credentials > OAuth client ID**.
3. Select **Web application** as application type.
4. Set **Authorized redirect URIs**:
   - `http://localhost:8000/api/auth/google/callback` (for local development)
5. Save your **Client ID** and **Client Secret**.

---

## 3. Google Cloud Pub/Sub Setup for Real-Time Watch

Gmail uses Google Cloud Pub/Sub to push real-time mailbox event notifications.

### Step 1: Create Pub/Sub Topic
1. Go to **Pub/Sub > Topics** in Google Cloud Console.
2. Create a topic, e.g., `gmail-notifications`.
3. Note the topic string: `projects/<your-gcp-project-id>/topics/gmail-notifications`.

### Step 2: Grant Gmail Push Publishing Rights
Gmail's push service needs permission to publish to your topic:
1. In the topic details, go to the **Permissions** tab.
2. Click **Add Principal**.
3. Principal: `gmail-api-push@system.gserviceaccount.com`.
4. Role: `Pub/Sub Publisher`.
5. Click **Save**.

### Step 3: Configure Push Subscription
1. Under your topic, create a **Push Subscription**.
2. Set Endpoint URL to your public webhook endpoint:
   - For local development: Use `ngrok` or similar tunnel (e.g., `https://your-tunnel.ngrok-free.app/api/webhooks/google/gmail`).
   - For production: Your public domain HTTPS endpoint.

---

## 4. Environment Configuration

Configure your environment variables in `.env` (derived from `.env.example`):

```bash
# Google Cloud OAuth 2.0
GOOGLE_CLIENT_ID="your-client-id.apps.googleusercontent.com"
GOOGLE_CLIENT_SECRET="your-client-secret"
GOOGLE_REDIRECT_URI="http://localhost:8000/api/auth/google/callback"
GOOGLE_OAUTH_SCOPES="https://www.googleapis.com/auth/gmail.readonly"

# Google Cloud Pub/Sub
GOOGLE_PUBSUB_TOPIC="projects/your-gcp-project-id/topics/gmail-notifications"
```

---

## 5. Local Development Workflow

### Connecting a Mailbox via OAuth
1. Initiate the OAuth flow by visiting:
   ```http
   GET http://localhost:8000/api/auth/google/login
   ```
   This returns the Google authorization URL with single-use CSRF state token:
   ```json
   {
     "authorization_url": "https://accounts.google.com/o/oauth2/v2/auth?...",
     "state": "..."
   }
   ```
2. Open the `authorization_url` in a browser and grant consent.
3. Google redirects to:
   ```http
   GET /api/auth/google/callback?code=4/0A...&state=...
   ```
4. The backend exchanges the code for offline access credentials, fetches your Gmail profile, registers the `Mailbox` entity, and returns:
   ```json
   {
     "status": "connected",
     "provider": "gmail",
     "account_email": "analyst@gmail.com",
     "mailbox_id": 1
   }
   ```

### Activating Mailbox Watch
Start push monitoring for the connected mailbox:
```http
POST /api/mailboxes/1/watch
```
Response:
```json
{
  "status": "watching",
  "mailbox_id": 1,
  "account_email": "analyst@gmail.com",
  "history_id": "891234",
  "expiration": "2026-09-26T10:00:00Z",
  "topic": "projects/your-project/topics/gmail-notifications"
}
```

### Ingesting Pub/Sub Notifications
When an email arrives, Google Pub/Sub POSTs a push message:
```http
POST /api/webhooks/google/gmail
Content-Type: application/json

{
  "message": {
    "data": "eyJlbWFpbEFkZHJlc3MiOiAiYW5hbHlzdEBnbWFpbC5jb20iLCAiaGlzdG9yeUlkIjogODkxMjM1fQ==",
    "messageId": "pubsub-msg-123",
    "publishTime": "2026-09-19T10:00:00Z"
  }
}
```
The webhook returns `200 OK` instantly, schedules `sync_gmail_mailbox` in the background, checks message idempotency, parses the email into `NormalizedEmail`, and executes `AnalysisPipeline`.

---

## 6. Token Security & Production Considerations

| Component | Local MVP Implementation | Production Recommendation |
|---|---|---|
| **Token Storage** | SQLite (`credentials_data` isolated behind `TokenStore`) | AWS Secrets Manager, HashiCorp Vault, or KMS-encrypted database columns |
| **Logging** | Token strings, auth headers, and secrets are strictly redacted and never logged | Automated log scrubbing & SIEM audit logging |
| **Token Refresh** | Automatic refresh on expiry via `TokenStore.get_credentials()` | Automatic refresh with distributed lock / secret cache |
| **OAuth State** | Single-use cryptographically random token with 10-minute TTL | Redis TTL cache or signed JWT state |
| **Scopes** | Restricted to `gmail.readonly` | Minimum privilege principle maintained |
