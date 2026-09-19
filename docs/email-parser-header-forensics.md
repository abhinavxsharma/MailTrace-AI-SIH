# MAILTRACE AI — Email Parser & Header Forensics (Chunk 2/7)

## Overview

Chunk 2 of MAILTRACE AI implements the **Email Parser** and **Header Forensics** pipeline. It accepts the in-memory `NormalizedEmail` object produced by the Gmail connector (Chunk 1) or in-memory MIME messages, extracts structured components, parses routing/identity headers, and evaluates 13 deterministic forensic rules to produce structured forensic evidence.

```
Gmail API
    ↓
NormalizedEmail (Chunk 1)
    ↓
Email Parser (forensics/email_parser)
    ↓
Header Parser (forensics/headers/parser.py)
    ↓
Header Forensics (forensics/headers/forensics.py)
    ↓
Structured Forensic Evidence (HeaderForensicResult)
```

---

## Architectural Boundaries

> [!IMPORTANT]
> **Authentication Boundary**:
> Chunk 2 parses authentication-related headers (such as `Authentication-Results`, `Received-SPF`, `DKIM-Signature`) as **raw data only**.
> Chunk 2 does **NOT** verify SPF, DKIM, or DMARC. Verification belongs strictly to **Chunk 3**.

> [!IMPORTANT]
> **No Verdicts or Scores**:
> Chunk 2 does not generate phishing verdicts, maliciousness classifications, or risk scores. Severities are strictly bounded to `INFO`, `LOW`, and `MEDIUM`.

---

## 1. Input Specifications

The primary input to the forensic pipeline is `NormalizedEmail` (`backend/app/services/mail/models.py`), created by Chunk 1's `message_fetcher.fetch_and_normalize()`.

The parser also accepts in-memory MIME strings, bytes, or `email.message.Message` instances for offline forensic analysis.

```python
from app.services.mail.models import NormalizedEmail
from forensics.email_parser import parse_email
from forensics.headers import analyze_headers

# Parse NormalizedEmail into ParsedEmail
parsed_email = parse_email(normalized_email)

# Run deterministic header forensics
forensic_result = analyze_headers(parsed_email)
```

---

## 2. Parser Flow

1. **Header Parsing**: All headers are extracted into `ParsedHeader` objects preserving order, casing, and duplicate occurrences. Multiline folded headers are unfolded per RFC 5322.
2. **Address Parsing**: Identity headers (`From`, `To`, `Cc`, `Bcc`, `Reply-To`, `Sender`, `Return-Path`) are parsed into typed `ParsedAddress` objects with normalized lowercased emails and domains.
3. **MIME Tree Walking**: For MIME emails, text and HTML bodies are extracted, and attachment metadata is collected without reading or saving payloads to disk.
4. **URL Extraction**: URLs in plain text and HTML are extracted and parsed into structured `ExtractedUrl` components.
5. **Received Chain**: `Received` headers are parsed top-to-bottom into structured `ReceivedHop` objects.
6. **Header Forensics**: The `ParsedEmail` is analyzed by 13 deterministic forensic rules, producing a `HeaderForensicResult`.

---

## 3. Address Normalization

The parser extracts addresses via `email.utils.parseaddr` and `email.utils.getaddresses` into `ParsedAddress`:

- `display_name`: Human-readable display name, unquoted and RFC 2047 decoded.
- `email`: Normalized lowercased email address (e.g. `john.doe@example.com`).
- `local_part`: Part before the `@` (e.g. `john.doe`).
- `domain`: Lowercased domain part (e.g. `example.com`).
- `original_value`: Original raw string preserved for evidence.

No external DNS or reputation lookups are performed during address normalization.

---

## 4. Header Normalization & Case-Insensitivity

- **Case-Insensitive Access**: `ParsedEmail.get_header("from")`, `get_headers("received")`, and `get_parsed_headers("subject")` allow case-insensitive access.
- **Folding Unfolding**: Multiline headers containing CRLF (or LF) followed by whitespace are unfolded into single-line strings.
- **Preservation of Duplicates**: RFC 5322 identity headers (`From`, `Subject`, `Date`, etc.) and `Received` headers are never silently dropped or collapsed into sets.

---

## 5. Received Chain Analysis

Each `Received` header is converted to a `ReceivedHop`:

- `original_value`: Full unedited header string.
- `from_host`: Extracted transmitting host / IP.
- `by_host`: Extracted receiving host / IP.
- `protocol`: Extracted transfer protocol (e.g. `ESMTPS`, `SMTP`).
- `id`: Extracted hop identifier / queue ID.
- `for_recipient`: Extracted recipient envelope address.
- `timestamp`: UTC-aware `datetime` parsed from the hop date.

Parsing is **resilient**: any unparseable or absent clauses remain `None`. The parser never crashes on unusual or proprietary MTA headers. No reverse DNS or GeoIP lookups are performed.

---

## 6. Deterministic Forensic Findings

The forensics engine evaluates 13 rules:

| Code | Category | Severity | Description |
| :--- | :--- | :--- | :--- |
| `FROM_REPLY_TO_MISMATCH` | `identity` | `MEDIUM` | `From` and `Reply-To` addresses differ |
| `FROM_RETURN_PATH_MISMATCH` | `identity` | `LOW` | `From` and `Return-Path` domains differ |
| `FROM_SENDER_MISMATCH` | `identity` | `LOW` | `From` and `Sender` addresses differ |
| `MISSING_FROM` | `identity` | `MEDIUM` | Mandatory `From` header is absent or empty |
| `MISSING_DATE` | `header_integrity` | `LOW` | `Date` header is absent |
| `MISSING_MESSAGE_ID` | `header_integrity` | `LOW` | `Message-ID` header is absent |
| `MISSING_RETURN_PATH` | `routing` | `INFO` | `Return-Path` header is absent (observation) |
| `UNUSUAL_REPLY_TO` | `identity` | `LOW` | `Reply-To` is empty or specifies multiple addresses |
| `MULTIPLE_FROM` | `identity` | `MEDIUM` | Multiple addresses in `From` or duplicate `From` headers |
| `DUPLICATE_IDENTITY_HEADERS` | `header_integrity` | `MEDIUM` | Single-occurrence identity headers appear multiple times |
| `INVALID_DATE` | `header_integrity` | `MEDIUM` | `Date` header is present but cannot be parsed |
| `MALFORMED_MESSAGE_ID` | `header_integrity` | `LOW` | `Message-ID` does not match `<id@host>` syntax |
| `FOLDED_HEADER_WHITESPACE` | `header_integrity` | `INFO` | Header contains multiline folded whitespace |

### Finding Structure
```json
{
    "code": "FROM_REPLY_TO_MISMATCH",
    "category": "identity",
    "severity": "MEDIUM",
    "description": "From and Reply-To addresses differ.",
    "evidence": {
        "from": "alice@example.com",
        "reply_to": "billing@other-example.com"
    },
    "related_headers": ["From", "Reply-To"]
}
```

---

## 7. URL Extraction

URLs are extracted from both plain text and HTML bodies:
- Extracted fields: `original_url`, `scheme`, `host`, `port`, `path`, `query`.
- URLs are deduplicated while preserving order of discovery.
- **Security Boundary**: The parser never fetches URLs, follows redirects, performs DNS lookups, or performs reputation checks.

---

## 8. Attachment Metadata

Attachments are exposed purely via metadata (`AttachmentMetadata`):
- `filename`: Filename from `Content-Disposition` or `Content-Type`.
- `content_type`: MIME content type (e.g. `application/pdf`).
- `size`: Size in bytes if available in memory.
- `content_id`: `Content-ID` header value.
- `disposition`: `attachment` or `inline`.

**Privacy Guarantee**:
Attachment content is **never** written to disk, executed, or sent to external scanners.

---

## 9. Privacy Model

1. **In-Memory Only**: All email representations remain in memory.
2. **No Temp Files**: `tempfile` is deliberately not imported or used in the `forensics` package.
3. **No Local Copies**: No `.eml`, `.mime`, or serialized email files are written to disk.
4. **Privacy Sentinel Tests**: Automated tests verify that `open()` is never called in write mode for `.eml` or `.mime` files and `tempfile` is not imported.

---

## 10. Chunk 3 Boundary

- **Chunk 2**: Parses and normalizes headers and addresses; extracts metadata; performs factual header heuristics; flags header anomalies.
- **Chunk 3**: Consumes `ParsedEmail` to verify **SPF**, **DKIM**, and **DMARC** authentication protocols against DNS records.
