# MAILTRACE AI — Gmail Mailbox Integration Guide

This guide details the end-to-end integration between **MAILTRACE AI** and **Google Gmail API** using Google Cloud OAuth 2.0 and Cloud Pub/Sub push notifications.

---

## 1. Architectural Overview & The Zero-.EML Mandate

```
Browser
  ↓
GET /api/auth/google/login
  ↓
Google OAuth consent
  ↓
GET /api/auth/google/callback
  ↓
Google authorization code
  ↓
Access + refresh credentials (TokenStore)
  ↓
Mailbox registered
  ↓
Gmail API connection
  ↓
Gmail watch (POST /api/mailboxes/{id}/watch)
  ↓
Pub/Sub notification (POST /api/webhooks/google/gmail)
  ↓
Gmail history list (historyId)
  ↓
Gmail message fetch (in-memory)
  ↓
NormalizedEmail (in-memory)
  ↓
AnalysisPipeline -> Case + Analysis + Deterministic Risk Scoring
```

### Why MAILTRACE AI Does Not Download .EML Files
1. **Security & Data Minimization**: Saving raw `.eml` files, raw MIME data, or attachments to disk creates severe data leakage, compliance (GDPR/HIPAA), and disk exhaustion risks.
2. **Real-time SOC Workflow**: SOC analysts monitor connected mailboxes automatically; requiring users to manually export and upload files breaks automated threat detection.
3. **In-Memory Streaming**: Messages are fetched directly from the Gmail API into runtime memory as canonical `NormalizedEmail` objects and inspected across analysis stages. Zero `.eml` files or temporary email files are written to disk. Only structured forensic metadata, indicators, and risk scores are persisted.

---

## 2. End-to-End Local Setup Sequence

Follow this exact 16-step sequence to configure and test real Gmail OAuth and Pub/Sub mailbox monitoring:

### Step 1: Create Google Cloud Project
1. Navigate to the [Google Cloud Console](https://console.cloud.google.com/).
2. Create a new Google Cloud project (e.g. `mailtrace-ai-dev`).

### Step 2: Enable Gmail API
1. In the console navigation menu, go to **APIs & Services > Library**.
2. Search for **Gmail API** and click **Enable**.

### Step 3: Enable Cloud Pub/Sub API
1. In **APIs & Services > Library**, search for **Cloud Pub/Sub API**.
2. Click **Enable**.

### Step 4: Configure OAuth Consent / Test User
1. Go to **APIs & Services > OAuth consent screen**.
2. Select **External** (or **Internal** if using Google Workspace).
3. Set App Name to `MAILTRACE AI` and provide support/developer contact emails.
4. Under **Scopes**, add the least-privilege read-only scope:
   - `https://www.googleapis.com/auth/gmail.readonly`
5. Under **Test users**, add your personal or testing Gmail account (`user@gmail.com`).
6. Save and continue.

### Step 5: Create Web OAuth Client
1. Go to **APIs & Services > Credentials**.
2. Click **Create Credentials > OAuth client ID**.
3. Select **Web application** as the Application type.
4. Name it `MAILTRACE AI Web Client`.

### Step 6: Configure Redirect URI
Under **Authorized redirect URIs**, add the exact callback URL:
- `http://127.0.0.1:8000/api/auth/google/callback`

*(Note: `http://localhost:8000/api/auth/google/callback` is also supported by the backend router and allowed redirect URI whitelist if registered in Google Cloud Console).*

Save the client. Copy the generated **Client ID** and **Client Secret**.

### Step 7: Configure Pub/Sub Topic
1. Go to **Pub/Sub > Topics** in the Google Cloud Console.
2. Click **Create Topic** with ID: `gmail-notifications`.
3. Note the fully qualified topic name:
   `projects/<GOOGLE_CLOUD_PROJECT_ID>/topics/gmail-notifications`
4. Grant Gmail Push permission to publish to your topic:
   - In the topic details, click the **Permissions** tab.
   - Click **Add Principal**.
   - Set **New principal**: `gmail-api-push@system.gserviceaccount.com`
   - Assign the **Pub/Sub Publisher** role.
   - Click **Save**.
5. Configure a Push Subscription (for receiving webhooks):
   - Click **Create Subscription** on the topic.
   - Set delivery type to **Push**.
   - For local development, point to your public tunnel URL (e.g. via ngrok / cloudflared):
     `https://<your-tunnel-subdomain>.ngrok-free.app/api/webhooks/google/gmail`

### Step 8: Configure Local .env
Create `.env` in the project root based on `.env.example`.
> **CRITICAL SECURITY NOTE**: Never commit `.env` or paste the Client Secret in chat, source files, or terminal logs. Enter it manually into `.env` only.

```bash
# Google Cloud OAuth 2.0 Credentials
GOOGLE_CLIENT_ID="<your-google-client-id>.apps.googleusercontent.com"
GOOGLE_CLIENT_SECRET="<manually-entered-secret>"
GOOGLE_REDIRECT_URI="http://127.0.0.1:8000/api/auth/google/callback"
GOOGLE_OAUTH_SCOPES="https://www.googleapis.com/auth/gmail.readonly"

# Google Cloud Pub/Sub Topic
GOOGLE_PUBSUB_TOPIC="projects/<GOOGLE_CLOUD_PROJECT_ID>/topics/gmail-notifications"
```

### Step 9: Start FastAPI
Run the local backend server using the virtual environment:
```bash
uvicorn backend.app.main:app --reload --port 8000
```
Verify the server is healthy:
```bash
curl http://127.0.0.1:8000/api/health
curl http://127.0.0.1:8000/api/ready
```

### Step 10: Open Google OAuth Login
Initiate the login handshake:
```bash
curl http://127.0.0.1:8000/api/auth/google/login
```
Response:
```json
{
  "authorization_url": "https://accounts.google.com/o/oauth2/v2/auth?...",
  "state": "..."
}
```
Open the `authorization_url` in your browser.

### Step 11: Connect Gmail
1. Log in with your test Gmail account and grant consent for `gmail.readonly`.
2. Google redirects your browser to:
   `http://127.0.0.1:8000/api/auth/google/callback?code=4/0A...&state=...`
3. The backend validates the CSRF state token, exchanges the authorization code with Google for access/refresh tokens, queries the Gmail profile, registers/updates the `Mailbox` in SQLite, and securely stores tokens via `TokenStore`.
4. Response is safe and never leaks credentials:
   ```json
   {
     "status": "connected",
     "provider": "gmail",
     "account_email": "analyst@gmail.com",
     "mailbox_id": 1
   }
   ```

### Step 12: Start Mailbox Watch
Call the watch endpoint for the connected mailbox ID:
```bash
curl -X POST http://127.0.0.1:8000/api/mailboxes/1/watch
```
Response:
```json
{
  "status": "watching",
  "mailbox_id": 1,
  "account_email": "analyst@gmail.com",
  "history_id": "1234567",
  "expiration": "2026-09-26T10:00:00Z",
  "topic": "projects/<GOOGLE_CLOUD_PROJECT_ID>/topics/gmail-notifications"
}
```
Gmail API is now monitoring the user's `INBOX` and pushing events to the Pub/Sub topic.

### Step 13: Send a Test Email
Send an email to the connected Gmail account from any external or secondary email address.

### Step 14: Observe the Webhook
Pub/Sub pushes a JSON notification to `POST /api/webhooks/google/gmail`:
```json
{
  "message": {
    "data": "eyJlbWFpbEFkZHJlc3MiOiAiYW5hbHlzdEBnbWFpbC5jb20iLCAiaGlzdG9yeUlkIjogMTIzNDU2OH0=",
    "messageId": "pubsub-msg-abc-123",
    "publishTime": "2026-09-19T10:05:00Z"
  }
}
```
The endpoint returns `200 OK` immediately (`{"status": "acknowledged"}`) and dispatches `sync_gmail_mailbox` to background tasks.

### Step 15: Fetch and Normalize the Message
In background processing:
1. `history.list(startHistoryId)` discovers the newly added message IDs.
2. Idempotency check verifies if `(provider="gmail", provider_message_id)` has already been processed.
3. Message data is retrieved directly via `messages.get(format="full")` into memory.
4. `parse_gmail_message()` converts headers, body parts, and metadata into a clean `NormalizedEmail` object in memory.
5. **No `.eml` files or raw MIME blobs are ever written to disk**.

### Step 16: Pass it to AnalysisPipeline
The in-memory `NormalizedEmail` is passed directly to:
```python
pipeline = AnalysisPipeline()
case = pipeline.run(normalized_email, mailbox_id=mailbox.id)
```
The analysis pipeline runs all registered analyzers (Forensics, Authentication, ML, Threat Intel, Correlation), evaluates deterministic risk scoring (0–100), and records structured results in the database:
- `Case` entity with assigned threat category and status.
- `Analysis` record with deterministic component scores.
- `AuditEvent` log entry.

---

## 3. Token Security & Safeguards

| Component | Implementation Safeguard |
|---|---|
| **Secret Protection** | `GOOGLE_CLIENT_SECRET` is only read from environment variables; never logged, committed, or exposed in endpoints. |
| **Token Storage** | Tokens are handled exclusively via the `TokenStore` abstraction. No `token.json` or `credentials.json` files exist. |
| **Automatic Token Refresh** | Expired access tokens are refreshed automatically by `TokenStore.get_credentials()` before any Gmail API call. |
| **Response Redaction** | Endpoints (`/login`, `/callback`, `/watch`, `/webhooks`) return only safe metadata (`mailbox_id`, `account_email`, `status`). Tokens are never returned. |
| **Strict Redirect URI Whitelist** | Rejects unrecognized redirect URIs, allowing only `http://127.0.0.1:8000/api/auth/google/callback` and `http://localhost:8000/api/auth/google/callback`. |
| **Topic Format Enforcement** | Validates Pub/Sub topic strictly matches `projects/<PROJECT_ID>/topics/<TOPIC_ID>`. |
