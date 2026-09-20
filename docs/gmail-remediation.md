# Gmail Remediation Actions — MAILTRACE AI (Chunk 3/5)

## Overview

MAILTRACE AI Chunk 3 replaces deferred placeholder security actions with real, authenticated Gmail operations for:
1. **Report Spam**
2. **Block Sender**
3. **Delete** (Trash)

All remediation actions operate directly against the Google Gmail REST API via the authenticated `GmailProviderClient`, respecting user privacy, data safety, and zero local disk persistence.

---

## 1. Minimum Required OAuth Scopes

MAILTRACE AI requests the minimum set of permissions required to perform forensics and active remediation. Under no circumstances is the all-encompassing `https://mail.google.com/` requested.

| Scope | Purpose | Operations Enabled |
|---|---|---|
| `https://www.googleapis.com/auth/gmail.readonly` | Read email headers, bodies, threads, and metadata | Pre-open scan, deep SOC investigation, message listing |
| `https://www.googleapis.com/auth/gmail.modify` | Modify message labels and move to trash | **Report Spam** (`messages.modify`), **Delete** (`messages.trash`) |
| `https://www.googleapis.com/auth/gmail.settings.basic` | Manage Gmail filters and routing rules | **Block Sender** (`users.settings.filters`) |

### Configuration (`backend/app/core/config.py`)
```python
google_oauth_scopes: Union[list[str], str] = [
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/gmail.settings.basic",
]
```

---

## 2. Remediation Actions Specification

### 2.1 Report Spam
- **Endpoint**: `POST /api/mailboxes/{mailbox_id}/messages/{message_id}/report-spam`
- **Underlying Gmail API**: `users.messages.modify`
- **Payload**:
  ```json
  {
    "addLabelIds": ["SPAM"],
    "removeLabelIds": ["INBOX"]
  }
  ```
- **Response Schema**:
  ```json
  {
    "success": true,
    "action": "REPORT_SPAM",
    "message_id": "18e9a2b...",
    "status": "REPORTED"
  }
  ```
- **Behavior**:
  - Adds the system `SPAM` label and removes `INBOX`.
  - Removes the message from the active inbox view.
  - Helps train Gmail's native spam classification filters.

### 2.2 Delete (Safe Trash)
- **Endpoint**: `POST /api/mailboxes/{mailbox_id}/messages/{message_id}/delete`
- **Underlying Gmail API**: `users.messages.trash`
- **Response Schema**:
  ```json
  {
    "success": true,
    "action": "DELETE",
    "message_id": "18e9a2b...",
    "status": "TRASHED"
  }
  ```
- **Behavior**:
  - Moves the email to Gmail Trash rather than permanent, irreversible purge (`messages.delete`).
  - The message remains recoverable from Trash in the user's Gmail account for 30 days.
  - Immediately removes the email from the local inbox feed.

### 2.3 Block Sender
- **Endpoint**: `POST /api/mailboxes/{mailbox_id}/messages/{message_id}/block-sender`
- **Underlying Gmail API**: `users.settings.filters.list` and `users.settings.filters.create`
- **Implementation Mechanism**:
  1. Retrieves message metadata to read the `From` header.
  2. Extracts canonical sender address using Python `email.utils.parseaddr`. Validates standard email structure.
  3. Queries `users.settings.filters.list(userId="me")` to check for an existing block filter for that sender (**Idempotency**).
  4. If an existing filter matches `criteria.from == sender_email`:
     - Returns `{ "success": true, "action": "BLOCK_SENDER", "sender": sender, "filter_id": "...", "already_blocked": true }`.
     - Prevents duplicate filter accumulation.
  5. If not already blocked, creates filter with:
     ```json
     {
       "criteria": { "from": "attacker@evil.com" },
       "action": {
         "removeLabelIds": ["INBOX"],
         "addLabelIds": ["TRASH"]
       }
     }
     ```
  6. Returns `{ "success": true, "action": "BLOCK_SENDER", "sender": sender, "filter_id": "...", "already_blocked": false }`.

---

## 3. Scope / Re-Authentication Handling

If an existing mailbox was previously authorized with readonly permissions only, remediation requests detect the missing permission:
1. Active credential scopes are verified prior to API invocation.
2. If `gmail.modify` or `gmail.settings.basic` is missing, the backend returns HTTP 403:
   ```json
   {
     "detail": "Additional Gmail permission required. Reconnect Gmail to enable security actions.",
     "error": {
       "code": "INSUFFICIENT_PERMISSIONS",
       "message": "Additional Gmail permission required. Reconnect Gmail to enable security actions."
     }
   }
   ```
3. The frontend catches this code and prompts the user to reconnect their Gmail account to grant the required security actions.
4. Existing mailbox data and tokens remain intact without destructive revocation.

---

## 4. Audit Logging & Security Guarantees

Every remediation action is recorded using the structured JSON logging pipeline:
- Safe metadata recorded:
  - `mailbox_id`
  - `message_id`
  - `action` (`REPORT_SPAM`, `DELETE`, `BLOCK_SENDER`)
  - `sender` (for block sender)
  - `status` (`REPORTED`, `TRASHED`, filter ID)
  - `provider` (`gmail`)
  - `request_id` (correlation ID)
- **Strict Privacy Protections**:
  - OAuth tokens (access tokens, refresh tokens, client secrets) are **NEVER** logged.
  - Raw email bodies and MIME attachments are **NEVER** logged.
  - Zero files are written to the local filesystem during remediation.

---

## 5. UI Confirmation UX

For destructive and remediation actions:
- Clicking **Delete** opens a confirmation dialog: *"Move this email to Trash?"* with `[ Cancel ]` and `[ Move to Trash ]`.
- Clicking **Block Sender** opens a confirmation dialog: *"Block future messages from <sender>?"* with `[ Cancel ]` and `[ Block Sender ]`.
- Clicking **Report Spam** opens a confirmation dialog: *"Report this email as spam?"* with `[ Cancel ]` and `[ Report Spam ]`.
- Actions show real-time loading spinners while communicating with the Gmail API.
- Upon API success confirmation, local inbox state updates immediately without requiring a full page or mailbox reload.
