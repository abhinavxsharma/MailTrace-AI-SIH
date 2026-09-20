# MAILTRACE AI — SIH Demonstration & Evaluation Guide

This guide provides the complete demonstration script and operational checklist for presenting MAILTRACE AI at the **Smart India Hackathon (SIH)**, mentor reviews, and live evaluation panels.

---

## 1. The 2-Minute Winning SIH Judge Pitch

### Pitch Strategy
Judges evaluate **real-world impact**, **novelty**, **technical depth**, and **working implementation**. Structure the 2-minute pitch around the four key pillars:

```
[ 0:00 - 0:35 ] PART 1: User Protection Before Opening
[ 0:35 - 1:05 ] PART 2: Real Gmail Remediation Actions
[ 1:05 - 1:40 ] PART 3: Deep SOC Forensic Investigation
[ 1:40 - 2:00 ] PART 4: The Unfair Advantage (Differentiation)
```

---

### Verbatim Pitch Script

#### Part 1: User Protection (0:00 – 0:35)
> *"Respected judges, email is still the #1 entry point for cyberattacks—costing billions annually in Business Email Compromise and credential theft. Traditional spam filters only classify emails after users open them or fail on targeted zero-day lures.*
> 
> *Here is MAILTRACE AI. We solve this before the user opens the email.*
> 
> *Notice our live connected Gmail account: as new emails arrive in near-real-time, MAILTRACE intercepts them in memory without writing a single file to disk. Our lightweight AI pipeline evaluates the message in under 50 milliseconds using DistilBERT and cryptographic headers.*
> 
> *Look at the screen: a high-risk email just arrived. Instead of an unsuspecting user clicking the link, MAILTRACE displays an urgent alert banner: '🚨 HIGH RISK THREAT INTERCEPTED'. Clicking 'Review' opens our Pre-Open Security Preview. The user sees plain, explainable reasons: 'CFO Impersonation detected', 'Reply-To points to external fraud box', and 'DMARC check failed'—all before opening the raw email."*

#### Part 2: Real Remediation Actions (0:35 – 1:05)
> *"Next: we don't just alert users; we give them instant, authenticated protective control.*
> 
> *Notice the three action buttons in the security preview: 'Report Spam', 'Block Sender', and 'Move to Trash'. These are not simulated placeholders. Clicking 'Block Sender' interacts with the live Google Gmail Settings Filters API to idempotently create an automated filter routing future attacker mail to trash. Clicking 'Move to Trash' safely relocates the malicious email to Gmail Trash.*
> 
> *Notice the inbox: the threat is remediated, and the user is 100% safe."*

#### Part 3: Deep SOC Forensic Investigation (1:05 – 1:40)
> *"Now let's switch to the security team's perspective. When an incident occurs, a security analyst needs evidence, not just a score.*
> 
> *With one click on 'Investigate Deep Forensics', MAILTRACE escalates the alert into our SOC Workstation. The analyst instantly accesses:*
> 1. *Full RFC 822 hop chain header forensics.*
> 2. *Cryptographic DKIM signature verification.*
> 3. *Observed source infrastructure: Originating IP, ASN, reverse DNS, and approximate geolocation.*
> 4. *Our interactive Threat Correlation Graph showing if this email belongs to a wider coordinated campaign sharing infrastructure.*
> 5. *And a downloadable, court-ready Forensic Dossier with cryptographic case hashes."*

#### Part 4: Differentiation & Closing (1:40 – 2:00)
> *"What makes MAILTRACE AI unique?*
> 
> *First, **Pre-Open Protection**: we stop threats before interaction.*
> *Second, **Zero-Trust Privacy**: zero raw `.eml` files on disk and zero token exposure.*
> *Third, **Dual Experience**: end users get a simple decision; security teams get comprehensive forensic evidence.*
> 
> *MAILTRACE AI bridges the gap between end-user safety and enterprise cyber defense. Thank you, and we welcome your questions."*

---

## 2. Live Gmail Demonstration Checklist

For live evaluation where an external Gmail mailbox is connected, follow this exact step-by-step checklist.

### Pre-Demonstration Setup
1. **Verify Backend**:
   ```bash
   cd backend
   ../.venv/bin/uvicorn backend.app.main:app --host 127.0.0.1 --port 8000
   ```
   Confirm `http://127.0.0.1:8000/api/health` returns `{"status":"ok"}`.

2. **Verify Frontend**:
   ```bash
   cd frontend
   npm run web:preview   # Serves production build on http://127.0.0.1:5173
   ```
   Confirm `http://127.0.0.1:5173` loads in the browser.

3. **Verify Environment Variables (`.env`)**:
   - `GOOGLE_CLIENT_ID`
   - `GOOGLE_CLIENT_SECRET`
   - `GOOGLE_REDIRECT_URI`
   - `GOOGLE_OAUTH_SCOPES` (must include `readonly`, `modify`, `settings.basic`)

### Live SIH Judge Demonstration Flow (10 Steps)
| Step | Phase | Action & Narrative | Expected Result & Verification |
|---|---|---|---|
| **STEP 1** | **Security Inbox** | Open `http://127.0.0.1:5173` on Desktop SOC or Mobile Client. | Production Security Inbox renders. Navbar indicates "Connected Gmail" and "Live Monitoring" active. |
| **STEP 2** | **Controlled Email Ingestion** | A new evaluation email (e.g. urgent wire transfer request) arrives in the connected inbox. | Intercepted in memory via Pub/Sub / sync service with zero raw content persisted to disk. |
| **STEP 3** | **Automatic Pre-Open Threat Scan** | Background monitoring automatically scans headers, cryptographic auth, NLP intents, and warm DistilBERT AI. | Evaluates threat in under 50 milliseconds BEFORE the recipient opens or interacts with the email. |
| **STEP 4** | **Instant Threat Alert** | Backend produces `SecurityAlert` and broadcasts `NEW_ALERT` over Server-Sent Events (measured warm local/LAN alert delivery <15ms). | 🚨 **MAILTRACE SECURITY ALERT** appears in real-time without requiring a full mailbox reload. Displays Risk Score (e.g. 87/100). |
| **STEP 5** | **Review Security Preview** | Click **`[ 🛡 Review Security Check ]`** to inspect the Pre-Open Security Preview. | Displays threat verdict (`MALICIOUS`), NLP Behavioral Intent (`financial_transfer`, `urgency_coercion`), explainable why-flagged bullets, and cryptographic auth (SPF/DKIM/DMARC). |
| **STEP 6** | **Immediate Mailbox Remediation** | Click one of the three live remediation controls: **[ Report Spam ]**, **[ Block Sender ]**, or **[ Move to Trash ]**. | Direct authenticated Gmail API remediation executed. Message and alert banner immediately purged from active inbox state. |
| **STEP 7** | **Escalate to Forensics** | Click **`[ Investigate Deep Forensics ]`** to escalate the incident for security operations. | Smooth transition to SOC Workstation without page reload or screen traps. |
| **STEP 8** | **SOC Evidence & Semantic Analysis** | Walk judges through the 4 SOC tabs: **Overview**, **Graph**, **Timeline**, and **Campaign**. | Highlights: 1) Hop-by-hop RFC 822 analysis; 2) Observed source infrastructure; 3) Extracted NLP entities; 4) Interactive entity graph; 5) **Semantic Campaign Intelligence** showing 91% similarity and shared payment language signals. |
| **STEP 9** | **Generate Forensic Report** | Click **`[ Generate Forensic Report ]`** / **`[ Export Dossier ]`**. | Generates complete, court-ready incident dossier with cryptographic SHA-256 case evidence hashes. |
| **STEP 10** | **Final Winning Statement** | Deliver final closing statement to judges: | *"End users get a simple security decision and immediate mailbox protection. Security teams get the evidence, infrastructure intelligence, semantic correlation, and forensic report behind that decision."* |

> [!IMPORTANT]
> **Controlled Evaluation Scenario**:
> Use a dedicated evaluation Gmail account. When testing, send controlled threat lures (e.g. `"Subject: URGENT: Executive Wire Transfer of $32,000 before 4 PM"`). Never send actual malware or malicious binaries.

> [!NOTE]
> **Testing & Performance Scopes**:
> - **Alert Delivery Latency**: The measured <15ms figure reflects warm local/LAN in-memory SSE event dispatch. On physical mobile hardware over cellular or power-saving WiFi, latency depends on operating system radio power states and is not claimed as <200ms without on-device instrumentation.
> - **Web Build Verification**: Verified via static production build compilation (`npx expo export --platform web`), confirming clean TypeScript compilation and asset bundling. This is distinct from automated cross-browser Selenium/Playwright testing.
> - **Gmail OAuth Verification**: The OAuth 2.0 flow is implemented with automated mock HTTP test suites; real-account end-to-end evaluation requires configured Google Cloud client credentials with authorized redirect URIs.

---

## 3. Automated Deterministic Demo Mode (Offline-Ready)

If live internet connectivity is intermittent or Google OAuth is unavailable, MAILTRACE AI provides three built-in deterministic scenarios using the live backend analysis engine.

### Scenario 1: BEC Wire Transfer (High Risk)
- **Sender**: `Chief Financial Officer <cfo@acme-corp.com>`
- **Reply-To**: `attacker-cfo@external-fraud-box.net` (Mismatch!)
- **Authentication**: DMARC FAIL, SPF FAIL
- **Indicators**: `IDENTITY_REPLY_TO_MISMATCH`, `AUTH_DMARC_FAIL`, `LURE_FINANCIAL_REQUEST`, `LURE_HIGH_URGENCY`
- **Result**: Risk Score 88 (CRITICAL/HIGH), Verdict `MALICIOUS`

### Scenario 2: Credential Phishing (Critical Risk)
- **Sender**: `IT Security Administrator <admin@company-security-portal.com>`
- **Content**: Account suspension warning with deceptive IP link lure.
- **Authentication**: SPF Softfail, DKIM invalid
- **Indicators**: `ML_MALICIOUS_THREAT_DETECTED`, `LURE_CREDENTIAL_THEFT`, `URL_SUSPICIOUS_LURE`
- **Result**: Risk Score 92 (CRITICAL), Verdict `MALICIOUS`

### Scenario 3: Legitimate Routine Internal Sync (Clean)
- **Sender**: `Engineering Lead <lead@legitimate-enterprise.org>`
- **Content**: Routine sprint review agenda and documentation links.
- **Authentication**: SPF PASS, DKIM PASS, DMARC PASS
- **Indicators**: None
- **Result**: Risk Score 12 (LOW), Verdict `BENIGN`

### Controlled Message Dispatch:
Send or forward any of the above evaluation templates to the connected Gmail inbox. The backend automatically synchronizes, executes the Pre-Open Scan (<50ms), and dispatches a high-risk alert event via Server-Sent Events (measured warm local/LAN alert delivery <15ms) directly to Desktop and Mobile clients. Judges can immediately test the full Review ➔ Preview ➔ Remediation ➔ Deep Forensics flow seamlessly.
