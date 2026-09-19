"""In-memory parser converting Gmail API message resources into NormalizedEmail schemas.

Strict Architectural Rule:
All parsing is performed purely in memory. No .eml, raw MIME, or attachment files
are ever saved to disk.
"""

import base64
import html
import re
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any, Dict, List, Optional, Tuple

from backend.app.core.logging import logger
from backend.app.schemas.analysis import NormalizedEmail


def _decode_base64url(data_str: str) -> str:
    """Safely decode base64url-encoded string from Gmail API response."""
    if not data_str:
        return ""
    try:
        # Add necessary base64 padding
        padded = data_str + "=" * (-len(data_str) % 4)
        raw_bytes = base64.urlsafe_b64decode(padded.encode("utf-8"))
        return raw_bytes.decode("utf-8", errors="replace")
    except Exception as exc:
        logger.warning("Failed to decode base64url payload chunk: %s", str(exc))
        return ""


def _strip_html_tags(html_content: str) -> str:
    """Basic HTML tag stripping fallback for HTML-only emails."""
    text = re.sub(r"<style[\s\S]*?</style>", "", html_content, flags=re.IGNORECASE)
    text = re.sub(r"<script[\s\S]*?</script>", "", text, flags=re.IGNORECASE)
    text = re.sub(r"<br\s*/?>", "\n", text, flags=re.IGNORECASE)
    text = re.sub(r"</p>", "\n\n", text, flags=re.IGNORECASE)
    text = re.sub(r"<[^>]+>", "", text)
    return html.unescape(text).strip()


def _extract_body_and_attachments(
    payload: Dict[str, Any],
) -> Tuple[str, str, List[Dict[str, Any]]]:
    """Recursively traverse message parts to extract plaintext, html fallback, and attachment metadata.

    Attachments are NOT downloaded; only metadata is collected.
    """
    plain_text_parts: List[str] = []
    html_parts: List[str] = []
    attachments: List[Dict[str, Any]] = []

    def traverse(part: Dict[str, Any]) -> None:
        mime_type = part.get("mimeType", "")
        filename = part.get("filename", "")
        body_dict = part.get("body", {})

        # Attachment detection
        if filename:
            attachments.append({
                "filename": filename,
                "mime_type": mime_type,
                "size_bytes": body_dict.get("size", 0),
                "attachment_id": body_dict.get("attachmentId", ""),
            })
            return

        # Leaf body content
        data = body_dict.get("data")
        if data:
            decoded = _decode_base64url(data)
            if mime_type == "text/plain":
                plain_text_parts.append(decoded)
            elif mime_type == "text/html":
                html_parts.append(decoded)

        # Child multipart traversal
        for subpart in part.get("parts", []):
            traverse(subpart)

    traverse(payload)
    plain_body = "\n".join(plain_text_parts).strip()
    html_body = "\n".join(html_parts).strip()

    return plain_body, html_body, attachments


def parse_gmail_message(
    message_resource: Dict[str, Any],
    mailbox_id: Optional[int] = None,
) -> NormalizedEmail:
    """Convert a raw Gmail API message resource into our canonical in-memory NormalizedEmail schema.

    Args:
        message_resource: JSON resource dictionary returned from Gmail API messages().get(format="full").
        mailbox_id: Optional internal primary key ID of the associated Mailbox.

    Returns:
        NormalizedEmail ready for direct in-memory analysis by AnalysisPipeline.
    """
    provider_message_id = message_resource.get("id", "")
    thread_id = message_resource.get("threadId")
    payload = message_resource.get("payload", {})

    # Extract headers
    headers_list: List[Dict[str, str]] = []
    headers_dict: Dict[str, str] = {}
    for h in payload.get("headers", []):
        name = h.get("name", "")
        value = h.get("value", "")
        headers_list.append({"name": name, "value": value})
        headers_dict[name.lower()] = value

    sender = headers_dict.get("from", "unknown@sender.external")
    recipient = headers_dict.get("to", "unknown@recipient.internal")
    subject = headers_dict.get("subject", "(No Subject)")

    # Extract received timestamp
    received_at: Optional[datetime] = None
    internal_date_str = message_resource.get("internalDate")
    if internal_date_str:
        try:
            timestamp_ms = int(internal_date_str)
            received_at = datetime.fromtimestamp(timestamp_ms / 1000.0, tz=timezone.utc)
        except (ValueError, TypeError):
            received_at = None

    if received_at is None and "date" in headers_dict:
        try:
            received_at = parsedate_to_datetime(headers_dict["date"])
            if received_at.tzinfo is None:
                received_at = received_at.replace(tzinfo=timezone.utc)
        except Exception:
            received_at = datetime.now(timezone.utc)

    if received_at is None:
        received_at = datetime.now(timezone.utc)

    # Extract body in memory
    plain_body, html_body, attachments = _extract_body_and_attachments(payload)
    final_body = plain_body if plain_body else _strip_html_tags(html_body)

    # If attachments exist, record metadata in headers list for forensics pipeline
    if attachments:
        for att in attachments:
            headers_list.append({
                "name": "X-Attachment-Metadata",
                "value": f"name={att['filename']}; type={att['mime_type']}; size={att['size_bytes']}",
            })

    logger.debug(
        "Parsed Gmail message '%s' in memory (sender: %s, subject: %s, attachments: %d)",
        provider_message_id,
        sender,
        subject,
        len(attachments),
    )

    return NormalizedEmail(
        provider="gmail",
        provider_message_id=provider_message_id,
        thread_id=thread_id,
        sender=sender,
        recipient=recipient,
        subject=subject,
        body=final_body,
        headers=headers_list,
        received_at=received_at,
        mailbox_id=mailbox_id,
    )
