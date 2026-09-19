# MAILTRACE AI — Email Authentication Verification (Chunk 3/7)

## Overview

Chunk 3 implements the **Email Authentication Verification** engine in `forensics/authentication/`. It takes the structured `ParsedEmail` produced by Chunk 2 and performs in-memory verification of:

1. **SPF (Sender Policy Framework)** — RFC 7208
2. **DKIM (DomainKeys Identified Mail)** — RFC 6376
3. **Domain Alignment** — RFC 7489 (relaxed and strict modes)
4. **DMARC (Domain-based Message Authentication, Reporting, and Conformance)** — RFC 7489
5. **Authentication-Results Header Comparison** — RFC 7601 discrepancy analysis

```
ParsedEmail (from Chunk 2)
    ↓
SPF Verification (forensics/authentication/spf.py)
DKIM Verification (forensics/authentication/dkim.py)
Domain Alignment (forensics/authentication/alignment.py)
DMARC Evaluation (forensics/authentication/dmarc.py)
    ↓
Authentication-Results Discrepancy Detection
    ↓
AuthenticationResult (Structured Forensic Evidence)
```

---

## Architectural Boundaries

> [!IMPORTANT]
> **Forensic Signal Only — Not a Final Verdict**:
> Authentication failure is an objective **forensic signal**. It is **not** by itself a final malicious or phishing verdict.
> Legitimate emails frequently fail authentication due to mailing lists, forwarding, misconfigured DNS records, or multi-tenant relaying.
>
> Chunk 3 produces structured factual evidence for downstream risk fusion engines. It does **not** make maliciousness determinations or calculate risk scores.

---

## 1. SPF Verification (RFC 7208)

The SPF verifier (`forensics/authentication/spf.py`) evaluates whether a connecting MTA IP address was authorized by the envelope sender domain.

### Flow
1. **Identify Envelope Domain**: Extracted from `parsed_email.return_path.domain` (falls back to `from_address.domain`).
2. **Identify Connecting IP**: Extracted from the earliest external hop in `parsed_email.received_hops` or passed explicitly.
3. **Query SPF Record**: Retrieves DNS TXT records for the domain matching `v=spf1`.
4. **Evaluate Mechanisms**: Evaluates mechanisms (`ip4`, `ip6`, `a`, `mx`, `include`, `redirect`, `all`) against the connecting IP.
5. **Enforce RFC 7208 Limits**: Enforces a strict limit of 10 DNS lookups to prevent recursion loops or DoS amplification.

### Evaluation Statuses
- `PASS`: Connecting IP is authorized (`+` qualifier).
- `FAIL`: Connecting IP is explicitly unauthorized (`-` qualifier).
- `SOFTFAIL`: Connecting IP is unauthorized, but domain publisher requests non-rejection (`~` qualifier).
- `NEUTRAL`: Domain owner explicitly refuses to state authorization (`?` qualifier).
- `NONE`: No SPF record published on the domain.
- `TEMPERROR`: Transient DNS lookup failure.
- `PERMERROR`: Malformed SPF record (e.g. multiple SPF records, syntax error, or exceeded 10 DNS lookups).
- `UNAVAILABLE`: Domain could not be resolved or DNS service unavailable.
- `NOT_EVALUATED`: Missing connecting IP or missing envelope sender domain.

---

## 2. DKIM Verification (RFC 6376)

The DKIM verifier (`forensics/authentication/dkim.py`) cryptographically validates one or more `DKIM-Signature` headers using public keys retrieved from DNS.

### Flow
1. **Parse Signatures**: Extracts `v`, `a`, `d`, `s`, `c`, `h`, `bh`, `b` tags from all `DKIM-Signature` headers.
2. **Query Public Key**: Performs DNS TXT query at `<selector>._domainkey.<domain>`.
3. **Verify Cryptographic Signatures**: Uses `dkimpy` in memory to verify header hashes and RSA/Ed25519 signatures against the message content.
4. **Support Multiple Signatures**: Evaluates all signatures independently and reports both individual results and aggregated status.

### Status Classification
- `valid`: Public key retrieved and cryptographic signature verified successfully.
- `invalid`: Public key retrieved, but signature or body hash does not match (potential tampering or bad key).
- `missing`: No `DKIM-Signature` header present on the email.
- `unavailable`: Public key record not found in DNS (`<selector>._domainkey.<domain>`).
- `malformed`: `DKIM-Signature` header is missing mandatory tags (`d=`, `s=`, `b=`, `bh=`) or has invalid syntax.

---

## 3. Domain Alignment (RFC 7489 Section 3.1)

DMARC requires that the domain validated by SPF or DKIM aligns with the domain in the visible `From:` header.

### Alignment Modes
- **Relaxed (`r`)** (Default):
  - Organizational (registrable) domains must match.
  - Example: `mail.example.com` aligns with `example.com` and `news.example.com`.
- **Strict (`s`)**:
  - Fully qualified domain names (FQDN) must match exactly.
  - Example: `mail.example.com` does **not** align with `example.com`.

### Alignment Functions
- `check_spf_alignment(from_domain, return_path_domain, mode="relaxed") -> bool`
- `check_dkim_alignment(from_domain, dkim_domain, mode="relaxed") -> bool`
- `evaluate_alignment(...) -> AlignmentResult`

---

## 4. DMARC Evaluation (RFC 7489)

The DMARC evaluator (`forensics/authentication/dmarc.py`) checks the published DMARC policy on the `From` domain and calculates the resulting disposition.

### Policy Discovery
1. Query TXT at `_dmarc.<from_domain>`.
2. If absent and `<from_domain>` is a subdomain, query `_dmarc.<organizational_domain>`.

### Evaluation Rules
- **SPF DMARC Pass**: SPF status is `PASS` AND SPF domain aligns with `From` domain.
- **DKIM DMARC Pass**: At least one valid DKIM signature aligns with `From` domain.
- **Overall DMARC Result**:
  - `PASS`: If either SPF or DKIM passes DMARC. Applied disposition is `none`.
  - `FAIL`: If neither passes DMARC. Applied disposition is governed by `p=` (or `sp=` for subdomains):
    - `none`: Monitor only; no action requested.
    - `quarantine`: Treat message with suspicion (spam folder).
    - `reject`: Reject message at SMTP boundary.
  - `NONE`: No DMARC record found.
  - `PERMERROR`: Multiple DMARC records found, or invalid syntax.
  - `TEMPERROR`: DNS lookup error.

---

## 5. Upstream Authentication-Results Comparison

Email received via Gmail or corporate MTAs often already contains an `Authentication-Results` header (RFC 7601).

The orchestrator (`forensics/authentication/verifier.py`):
1. Parses claimed results for `spf`, `dkim`, and `dmarc` from the header.
2. Compares claimed results against locally verified results.
3. Records any `AuthenticationDiscrepancy`:
   ```json
   {
       "protocol": "spf",
       "header_claimed_result": "pass",
       "locally_verified_result": "fail",
       "description": "Upstream Authentication-Results claimed SPF 'pass', but local verification evaluated to 'fail'."
   }
   ```

### Discrepancy Context & Limitations
- Upstream MTAs see the original client connecting IP before internal network forwarding; local verification from Received headers may inspect a different hop.
- Upstream MTAs perform DKIM verification at time of receipt; subsequent forwarding or body modifications by gateways can break DKIM signatures locally.
- Both claimed and locally verified results are retained as evidence.

---

## 6. Privacy & Security Model

- **In-Memory Processing Only**: No raw message bytes, headers, or decoded bodies are written to disk.
- **No Temporary Files**: `tempfile` is deliberately not imported or used anywhere in `forensics/authentication/`.
- **No Unrestricted Live DNS in Tests**: All unit tests use a mock DNS resolver protocol, guaranteeing 100% offline, deterministic test execution.
