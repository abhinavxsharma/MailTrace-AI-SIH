"""
MAILTRACE AI — In-memory email parser.

Parses NormalizedEmail objects and in-memory MIME messages into structured
ParsedEmail representations. Extracts typed addresses, headers, attachments
metadata, and URLs entirely in memory.

PRIVACY GUARANTEE:
- No .eml or raw MIME files are saved.
- No temporary files are created (tempfile is not used).
- No attachment payloads are written to disk or executed.
- All operations are strictly in-memory.
"""

from __future__ import annotations

import email
import email.header
import email.message
import email.utils
import re
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit

try:
    from backend.app.schemas.analysis import NormalizedEmail
except ImportError:
    NormalizedEmail = None
from forensics.email_parser.models import (
    AttachmentMetadata,
    ExtractedUrl,
    ParsedAddress,
    ParsedEmail,
    ParsedHeader,
    ReceivedHop,
)
from forensics.headers.parser import parse_headers, parse_received_hop, unfold_header

# --------------------------------------------------------------------------- #
# Address parsing                                                              #
# --------------------------------------------------------------------------- #

def _decode_header_value(val: str) -> str:
    """Decode any RFC 2047 encoded-word strings into unicode."""
    if not val:
        return ""
    try:
        decoded_chunks = email.header.decode_header(val)
        parts: list[str] = []
        for chunk, charset in decoded_chunks:
            if isinstance(chunk, bytes):
                encoding = charset or "utf-8"
                try:
                    parts.append(chunk.decode(encoding, errors="replace"))
                except (LookupError, UnicodeError):
                    parts.append(chunk.decode("utf-8", errors="replace"))
            else:
                parts.append(str(chunk))
        return " ".join(parts).strip()
    except Exception:  # noqa: BLE001
        return val.strip()


def parse_address(addr_str: str) -> ParsedAddress:
    """
    Parse an RFC 5322 address string into a typed ``ParsedAddress``.

    Handles:
    - 'John Doe <john@example.com>'
    - '"John Doe" <john@example.com>'
    - 'john@example.com'
    - Malformed or partial strings

    Does NOT perform DNS or reputation lookups.
    """
    if not addr_str:
        return ParsedAddress(original_value=addr_str)

    try:
        display_name, raw_email = email.utils.parseaddr(addr_str)
    except Exception:  # noqa: BLE001
        display_name, raw_email = "", addr_str.strip()

    display_name = _decode_header_value(display_name).strip("\"' ")
    email_clean = raw_email.strip().lower()

    if "@" in email_clean:
        local_part, domain = email_clean.rsplit("@", 1)
    else:
        local_part = email_clean
        domain = ""

    return ParsedAddress(
        display_name=display_name,
        email=email_clean,
        local_part=local_part,
        domain=domain.lower(),
        original_value=addr_str,
    )


def parse_addresses(addr_str: str) -> list[ParsedAddress]:
    """
    Parse a comma-separated list of RFC 5322 addresses.
    """
    if not addr_str or not addr_str.strip():
        return []

    try:
        pairs = email.utils.getaddresses([addr_str])
    except Exception:  # noqa: BLE001
        pairs = []

    results: list[ParsedAddress] = []
    for display_name, raw_email in pairs:
        if not display_name and not raw_email:
            continue
        display_name = _decode_header_value(display_name).strip("\"' ")
        email_clean = raw_email.strip().lower()

        if "@" in email_clean:
            local_part, domain = email_clean.rsplit("@", 1)
        else:
            local_part = email_clean
            domain = ""

        orig = f'"{display_name}" <{raw_email}>' if display_name else raw_email

        results.append(
            ParsedAddress(
                display_name=display_name,
                email=email_clean,
                local_part=local_part,
                domain=domain.lower(),
                original_value=orig,
            )
        )

    # Fallback if getaddresses failed to extract anything from non-empty string
    if not results and addr_str.strip():
        results.append(parse_address(addr_str))

    return results


# --------------------------------------------------------------------------- #
# URL extraction                                                               #
# --------------------------------------------------------------------------- #

_URL_REGEX = re.compile(
    r"https?://[a-zA-Z0-9][-a-zA-Z0-9+&@#/%?=~_|!:,.;]*[a-zA-Z0-9+&@#/%=~_|]",
    re.IGNORECASE,
)
_HTML_HREF_REGEX = re.compile(
    r"""href=["'](https?://[^"'>\s]+)["']""",
    re.IGNORECASE,
)


def extract_urls(text: str | None, html: str | None) -> list[ExtractedUrl]:
    """
    Extract and structure URLs from text and HTML bodies in memory.

    Does NOT fetch URLs, follow redirects, perform DNS, or classify maliciousness.
    """
    raw_urls: list[str] = []

    if text:
        raw_urls.extend(_URL_REGEX.findall(text))

    if html:
        # Extract from href attributes
        raw_urls.extend(_HTML_HREF_REGEX.findall(html))
        # Also extract any plaintext URLs in HTML
        raw_urls.extend(_URL_REGEX.findall(html))

    # Deduplicate preserving order
    seen: set[str] = set()
    extracted: list[ExtractedUrl] = []

    for raw in raw_urls:
        clean = raw.rstrip(".,;)>]}")
        if not clean or clean in seen:
            continue
        seen.add(clean)

        try:
            parsed = urlsplit(clean)
            extracted.append(
                ExtractedUrl(
                    original_url=clean,
                    scheme=parsed.scheme.lower(),
                    host=(parsed.hostname or "").lower(),
                    port=parsed.port,
                    path=parsed.path,
                    query=parsed.query,
                )
            )
        except Exception:  # noqa: BLE001
            # Resilient: keep raw URL with empty parts on split error
            extracted.append(ExtractedUrl(original_url=clean))

    return extracted


# --------------------------------------------------------------------------- #
# Date & Reference helpers                                                     #
# --------------------------------------------------------------------------- #

def _parse_date(date_str: str | None) -> datetime | None:
    if not date_str:
        return None
    try:
        dt = email.utils.parsedate_to_datetime(date_str)
        return dt.astimezone(timezone.utc)
    except Exception:  # noqa: BLE001
        return None


def _parse_references(ref_str: str | None) -> list[str]:
    if not ref_str:
        return []
    # References are typically <msg-id> <msg-id>
    ids = re.findall(r"<[^>]+>", ref_str)
    if ids:
        return ids
    # Fallback to whitespace split
    return [s.strip() for s in ref_str.split() if s.strip()]


# --------------------------------------------------------------------------- #
# Email parser                                                                 #
# --------------------------------------------------------------------------- #

def parse_email(
    email_input: NormalizedEmail | str | bytes | email.message.Message,
) -> ParsedEmail:
    """
    Parse an email into a typed ``ParsedEmail`` model.

    Supports:
    - ``NormalizedEmail`` from Chunk 1 connector
    - Raw MIME strings or bytes (in memory)
    - Stdlib ``email.message.Message`` instances

    Handles plain text, HTML, multipart/alternative, multipart/mixed,
    nested multipart, missing bodies, and malformed optional fields.

    PRIVACY: Operates strictly in memory. Never creates or writes to files.
    """
    if isinstance(email_input, NormalizedEmail) or type(email_input).__name__ == "NormalizedEmail":
        return _parse_from_normalized(email_input)
    elif isinstance(email_input, (str, bytes, email.message.Message)):
        return _parse_from_mime(email_input)
    else:
        raise TypeError(f"Unsupported email input type: {type(email_input)}")


def _parse_from_normalized(norm: NormalizedEmail) -> ParsedEmail:
    """Build a ParsedEmail from a NormalizedEmail instance."""
    # 1. Normalize headers dictionary
    headers_dict: dict[str, str] = {}
    if isinstance(norm.headers, dict):
        headers_dict = {str(k).lower(): str(v) for k, v in norm.headers.items()}
    elif isinstance(norm.headers, list):
        for h in norm.headers:
            if isinstance(h, dict) and "name" in h and "value" in h:
                k = str(h["name"]).lower()
                v = str(h["value"])
                if k in headers_dict:
                    headers_dict[k] += f"; {v}"
                else:
                    headers_dict[k] = v

    header_list = parse_headers(headers_dict)

    # 2. Extract specific identity & routing headers
    from_raw = headers_dict.get("from") or getattr(norm, "sender", "")
    from_addr = parse_address(from_raw) if from_raw else None

    # Recipients (To, Cc, Bcc)
    to_raw = headers_dict.get("to") or getattr(norm, "recipient", "")
    to_addrs = parse_addresses(to_raw) if to_raw else []

    cc_raw = headers_dict.get("cc", "")
    cc_addrs = parse_addresses(cc_raw) if cc_raw else []

    bcc_raw = headers_dict.get("bcc", "")
    bcc_addrs = parse_addresses(bcc_raw) if bcc_raw else []

    reply_to_raw = headers_dict.get("reply-to", "")
    reply_to_addrs = parse_addresses(reply_to_raw) if reply_to_raw else []

    sender_raw = headers_dict.get("sender", "")
    sender_addr = parse_address(sender_raw) if sender_raw else None

    return_path_raw = headers_dict.get("return-path", "")
    return_path_addr = parse_address(return_path_raw) if return_path_raw else None

    # 3. Message IDs & References
    msg_id_header = headers_dict.get("message-id")
    in_reply_to = headers_dict.get("in-reply-to")
    references = _parse_references(headers_dict.get("references"))

    # 4. Received chain
    received_hops: list[ReceivedHop] = []
    received_header_val = headers_dict.get("received")
    if received_header_val:
        hop_texts = re.split(r";\s+(?=(?:from|by)\s+)", received_header_val, flags=re.IGNORECASE)
        for h_text in hop_texts:
            if h_text.strip():
                received_hops.append(parse_received_hop(h_text.strip()))

    # 5. Body parts & Extract URLs
    body_text = getattr(norm, "body_text", None) or getattr(norm, "body", "")
    body_html = getattr(norm, "body_html", None)
    urls = extract_urls(body_text, body_html)

    # 6. Date
    date_val = getattr(norm, "received_at", None) or _parse_date(headers_dict.get("date"))

    return ParsedEmail(
        message_id=getattr(norm, "provider_message_id", "") or "unknown",
        thread_id=getattr(norm, "thread_id", None) or "",
        from_address=from_addr,
        to_addresses=to_addrs,
        cc_addresses=cc_addrs,
        bcc_addresses=bcc_addrs,
        reply_to_addresses=reply_to_addrs,
        sender_address=sender_addr,
        return_path=return_path_addr,
        message_id_header=msg_id_header,
        in_reply_to=in_reply_to,
        references=references,
        date=date_val,
        subject=getattr(norm, "subject", "") or "",
        body_text=body_text,
        body_html=body_html,
        headers=header_list,
        received_hops=received_hops,
        attachments=[],
        extracted_urls=urls,
        raw_size_bytes=getattr(norm, "raw_size_bytes", None),
    )


def _parse_from_mime(raw_mime: str | bytes | email.message.Message) -> ParsedEmail:
    """
    Parse an email from raw MIME string, bytes, or email.message.Message.
    Operates strictly in memory.
    """
    if isinstance(raw_mime, str):
        msg = email.message_from_string(raw_mime)
    elif isinstance(raw_mime, bytes):
        msg = email.message_from_bytes(raw_mime)
    else:
        msg = raw_mime

    # 1. Headers list preserving order and duplicates
    raw_header_pairs: list[tuple[str, str]] = list(msg.items())
    header_list = parse_headers(raw_header_pairs)

    # 2. Received hops
    received_hops: list[ReceivedHop] = []
    for name, val in raw_header_pairs:
        if name.lower() == "received":
            received_hops.append(parse_received_hop(val))

    # 3. Addresses
    from_raw = msg.get("from", "")
    from_addr = parse_address(from_raw) if from_raw else None

    to_addrs = parse_addresses(msg.get("to", ""))
    cc_addrs = parse_addresses(msg.get("cc", ""))
    bcc_addrs = parse_addresses(msg.get("bcc", ""))
    reply_to_addrs = parse_addresses(msg.get("reply-to", ""))

    sender_raw = msg.get("sender", "")
    sender_addr = parse_address(sender_raw) if sender_raw else None

    return_path_raw = msg.get("return-path", "")
    return_path_addr = parse_address(return_path_raw) if return_path_raw else None

    # 4. Routing & IDs
    msg_id_header = msg.get("message-id")
    in_reply_to = msg.get("in-reply-to")
    references = _parse_references(msg.get("references"))
    date_val = _parse_date(msg.get("date"))
    subject = _decode_header_value(msg.get("subject", ""))

    # 5. Walk MIME tree for bodies and attachments
    body_text_parts: list[str] = []
    body_html_parts: list[str] = []
    attachments: list[AttachmentMetadata] = []

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type().lower()
            content_disposition = part.get_content_disposition()
            filename = part.get_filename() or ""
            content_id = part.get("content-id")

            # Check if this part is an attachment
            is_attachment = (
                content_disposition == "attachment"
                or (filename != "")
                or (
                    content_type not in ("text/plain", "text/html")
                    and not content_type.startswith("multipart/")
                )
            )

            if is_attachment:
                # Calculate size in memory without writing to disk
                payload = part.get_payload(decode=True)
                size = len(payload) if payload is not None else None
                attachments.append(
                    AttachmentMetadata(
                        filename=filename,
                        content_type=content_type,
                        size=size,
                        content_id=content_id,
                        disposition=content_disposition,
                    )
                )
            elif content_type == "text/plain":
                payload = part.get_payload(decode=True)
                if payload:
                    charset = part.get_content_charset() or "utf-8"
                    try:
                        body_text_parts.append(payload.decode(charset, errors="replace"))
                    except (LookupError, UnicodeError):
                        body_text_parts.append(payload.decode("utf-8", errors="replace"))
            elif content_type == "text/html":
                payload = part.get_payload(decode=True)
                if payload:
                    charset = part.get_content_charset() or "utf-8"
                    try:
                        body_html_parts.append(payload.decode(charset, errors="replace"))
                    except (LookupError, UnicodeError):
                        body_html_parts.append(payload.decode("utf-8", errors="replace"))
    else:
        content_type = msg.get_content_type().lower()
        content_disposition = msg.get_content_disposition()
        filename = msg.get_filename() or ""
        content_id = msg.get("content-id")

        if content_disposition == "attachment" or filename:
            payload = msg.get_payload(decode=True)
            size = len(payload) if payload is not None else None
            attachments.append(
                AttachmentMetadata(
                    filename=filename,
                    content_type=content_type,
                    size=size,
                    content_id=content_id,
                    disposition=content_disposition,
                )
            )
        elif content_type == "text/plain":
            payload = msg.get_payload(decode=True)
            if payload:
                charset = msg.get_content_charset() or "utf-8"
                try:
                    body_text_parts.append(payload.decode(charset, errors="replace"))
                except (LookupError, UnicodeError):
                    body_text_parts.append(payload.decode("utf-8", errors="replace"))
        elif content_type == "text/html":
            payload = msg.get_payload(decode=True)
            if payload:
                charset = msg.get_content_charset() or "utf-8"
                try:
                    body_html_parts.append(payload.decode(charset, errors="replace"))
                except (LookupError, UnicodeError):
                    body_html_parts.append(payload.decode("utf-8", errors="replace"))

    body_text = "".join(body_text_parts) if body_text_parts else None
    body_html = "".join(body_html_parts) if body_html_parts else None

    # 6. Extract URLs
    urls = extract_urls(body_text, body_html)

    # Use Message-ID as message_id if available, or generate a placeholder
    msg_id = msg_id_header.strip("<> ") if msg_id_header else ""

    return ParsedEmail(
        message_id=msg_id,
        thread_id="",
        from_address=from_addr,
        to_addresses=to_addrs,
        cc_addresses=cc_addrs,
        bcc_addresses=bcc_addrs,
        reply_to_addresses=reply_to_addrs,
        sender_address=sender_addr,
        return_path=return_path_addr,
        message_id_header=msg_id_header,
        in_reply_to=in_reply_to,
        references=references,
        date=date_val,
        subject=subject,
        body_text=body_text,
        body_html=body_html,
        mime_type=msg.get_content_type(),
        headers=header_list,
        received_hops=received_hops,
        attachments=attachments,
        extracted_urls=urls,
    )
