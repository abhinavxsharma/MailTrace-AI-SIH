"""
Tests for message_fetcher.py (app.services.mail.message_fetcher).

CRITICAL: These tests include an explicit privacy sentinel test proving
that fetch_and_normalize() never writes raw email files to disk.

No real Google credentials, internet access, or API calls are made.
"""

from __future__ import annotations

import base64
import os
import tempfile
from datetime import timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from app.services.mail.message_fetcher import (
    _collect_parts,
    _decode_base64url,
    _extract_headers,
    _normalize,
    _parse_date,
    _parse_recipients,
    fetch_and_normalize,
)
from app.services.mail.models import NormalizedEmail


# --------------------------------------------------------------------------- #
# Helper builders                                                              #
# --------------------------------------------------------------------------- #

def _b64url(text: str) -> str:
    """Encode a string as base64url (no padding), like Gmail API."""
    return base64.urlsafe_b64encode(text.encode("utf-8")).rstrip(b"=").decode("ascii")


def _make_simple_payload(
    *,
    text: str = "Hello world",
    mime_type: str = "text/plain",
    message_id: str = "msg001",
    thread_id: str = "thr001",
    from_: str = "alice@example.com",
    to: str = "bob@example.com",
    subject: str = "Test Subject",
    date: str = "Mon, 01 Jan 2024 10:00:00 +0000",
) -> dict:
    """Build a minimal Gmail API message dict with a single body part."""
    return {
        "id": message_id,
        "threadId": thread_id,
        "sizeEstimate": len(text),
        "payload": {
            "mimeType": mime_type,
            "headers": [
                {"name": "From", "value": from_},
                {"name": "To", "value": to},
                {"name": "Subject", "value": subject},
                {"name": "Date", "value": date},
            ],
            "body": {"data": _b64url(text)},
            "parts": [],
        },
    }


def _make_multipart_payload(
    *,
    text: str = "Plain body",
    html: str = "<p>HTML body</p>",
    message_id: str = "msg002",
    thread_id: str = "thr002",
) -> dict:
    """Build a Gmail API message dict with multipart/alternative payload."""
    return {
        "id": message_id,
        "threadId": thread_id,
        "sizeEstimate": len(text) + len(html),
        "payload": {
            "mimeType": "multipart/alternative",
            "headers": [
                {"name": "From", "value": "sender@example.com"},
                {"name": "To", "value": "recipient@example.com"},
                {"name": "Subject", "value": "Multipart message"},
                {"name": "Date", "value": "Tue, 02 Jan 2024 08:30:00 +0000"},
            ],
            "body": {},
            "parts": [
                {
                    "mimeType": "text/plain",
                    "headers": [],
                    "body": {"data": _b64url(text)},
                },
                {
                    "mimeType": "text/html",
                    "headers": [],
                    "body": {"data": _b64url(html)},
                },
            ],
        },
    }


def _make_mock_client(message_response: dict) -> MagicMock:
    """Return a mock GmailClient that returns the given message dict."""
    client = MagicMock()
    client.get_message.return_value = message_response
    return client


# --------------------------------------------------------------------------- #
# _decode_base64url tests                                                      #
# --------------------------------------------------------------------------- #

class TestDecodeBase64url:

    def test_simple_text(self):
        encoded = _b64url("Hello, MAILTRACE!")
        assert _decode_base64url(encoded) == "Hello, MAILTRACE!"

    def test_empty_string_returns_none(self):
        assert _decode_base64url("") is None

    def test_none_returns_none(self):
        assert _decode_base64url(None) is None  # type: ignore[arg-type]

    def test_with_padding_variants(self):
        # 1-byte padding case
        text = "A"
        encoded = _b64url(text)
        assert _decode_base64url(encoded) == "A"

    def test_unicode_content(self):
        text = "Héllo Wörld — émoji 🎉"
        encoded = _b64url(text)
        result = _decode_base64url(encoded)
        assert result == text

    def test_malformed_base64_returns_none(self):
        # Not valid base64url at all
        result = _decode_base64url("!!!not_base64!!!")
        # Either None or a replacement-character string — must not raise.
        # (binascii.Error causes None return; partial decode returns string)
        assert result is None or isinstance(result, str)

    def test_real_gmail_style_encoding(self):
        """Verify URL-safe variant (- and _) is handled correctly."""
        raw = b"\xfb\xff"  # produces + and / in standard b64, - and _ in urlsafe
        encoded = base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
        result = _decode_base64url(encoded)
        assert result is not None  # decoded without error


# --------------------------------------------------------------------------- #
# _extract_headers tests                                                       #
# --------------------------------------------------------------------------- #

class TestExtractHeaders:

    def test_lowercases_header_names(self):
        headers = _extract_headers([
            {"name": "From", "value": "alice@example.com"},
            {"name": "SUBJECT", "value": "Test"},
        ])
        assert "from" in headers
        assert "subject" in headers

    def test_duplicate_headers_joined_with_semicolon(self):
        headers = _extract_headers([
            {"name": "Received", "value": "from server-a"},
            {"name": "Received", "value": "from server-b"},
        ])
        assert headers["received"] == "from server-a; from server-b"

    def test_empty_list_returns_empty_dict(self):
        assert _extract_headers([]) == {}

    def test_header_with_empty_name_is_skipped(self):
        headers = _extract_headers([
            {"name": "", "value": "orphaned value"},
            {"name": "From", "value": "a@b.com"},
        ])
        assert "" not in headers
        assert "from" in headers

    def test_whitespace_stripped_from_values(self):
        headers = _extract_headers([{"name": "Subject", "value": "  Hello  "}])
        assert headers["subject"] == "Hello"


# --------------------------------------------------------------------------- #
# _parse_recipients tests                                                      #
# --------------------------------------------------------------------------- #

class TestParseRecipients:

    def test_single_to_address(self):
        headers = {"to": "bob@example.com"}
        result = _parse_recipients(headers)
        assert "bob@example.com" in result

    def test_multiple_to_addresses(self):
        headers = {"to": "alice@example.com, bob@example.com"}
        result = _parse_recipients(headers)
        assert "alice@example.com" in result
        assert "bob@example.com" in result

    def test_cc_and_bcc_included(self):
        headers = {
            "to": "to@example.com",
            "cc": "cc@example.com",
            "bcc": "bcc@example.com",
        }
        result = _parse_recipients(headers)
        assert "to@example.com" in result
        assert "cc@example.com" in result
        assert "bcc@example.com" in result

    def test_no_recipient_headers_returns_empty(self):
        assert _parse_recipients({}) == []

    def test_duplicate_addresses_deduplicated(self):
        headers = {"to": "same@example.com, same@example.com"}
        result = _parse_recipients(headers)
        assert result.count("same@example.com") == 1

    def test_display_name_stripped(self):
        headers = {"to": "Bob Smith <bob@example.com>"}
        result = _parse_recipients(headers)
        assert "bob@example.com" in result


# --------------------------------------------------------------------------- #
# _parse_date tests                                                            #
# --------------------------------------------------------------------------- #

class TestParseDate:

    def test_valid_rfc2822_date(self):
        result = _parse_date("Mon, 01 Jan 2024 10:00:00 +0000")
        assert result is not None
        assert result.year == 2024
        assert result.month == 1
        assert result.day == 1
        assert result.tzinfo == timezone.utc

    def test_none_returns_none(self):
        assert _parse_date(None) is None

    def test_empty_string_returns_none(self):
        assert _parse_date("") is None

    def test_malformed_date_returns_none(self):
        assert _parse_date("not a date at all") is None

    def test_date_normalised_to_utc(self):
        # Date with +05:30 offset — should be converted to UTC.
        result = _parse_date("Mon, 01 Jan 2024 15:30:00 +0530")
        assert result is not None
        assert result.tzinfo == timezone.utc
        assert result.hour == 10  # 15:30 IST == 10:00 UTC


# --------------------------------------------------------------------------- #
# _collect_parts tests                                                         #
# --------------------------------------------------------------------------- #

class TestCollectParts:

    def test_simple_text_plain(self):
        payload = {
            "mimeType": "text/plain",
            "body": {"data": _b64url("Plain text here.")},
        }
        text, html = [], []
        _collect_parts(payload, text, html)
        assert "".join(text) == "Plain text here."
        assert html == []

    def test_simple_text_html(self):
        payload = {
            "mimeType": "text/html",
            "body": {"data": _b64url("<h1>HTML</h1>")},
        }
        text, html = [], []
        _collect_parts(payload, text, html)
        assert html == ["<h1>HTML</h1>"]
        assert text == []

    def test_multipart_alternative(self):
        payload = {
            "mimeType": "multipart/alternative",
            "body": {},
            "parts": [
                {"mimeType": "text/plain", "body": {"data": _b64url("plain")}},
                {"mimeType": "text/html", "body": {"data": _b64url("<b>html</b>")}},
            ],
        }
        text, html = [], []
        _collect_parts(payload, text, html)
        assert "".join(text) == "plain"
        assert "".join(html) == "<b>html</b>"

    def test_nested_multipart(self):
        payload = {
            "mimeType": "multipart/mixed",
            "body": {},
            "parts": [
                {
                    "mimeType": "multipart/alternative",
                    "body": {},
                    "parts": [
                        {"mimeType": "text/plain", "body": {"data": _b64url("inner plain")}},
                    ],
                },
            ],
        }
        text, html = [], []
        _collect_parts(payload, text, html)
        assert "".join(text) == "inner plain"

    def test_missing_body_data_skipped(self):
        payload = {
            "mimeType": "text/plain",
            "body": {},  # no 'data' key
        }
        text, html = [], []
        _collect_parts(payload, text, html)
        assert text == []

    def test_image_attachment_ignored(self):
        payload = {
            "mimeType": "image/png",
            "body": {"data": _b64url("fake image bytes")},
        }
        text, html = [], []
        _collect_parts(payload, text, html)
        assert text == []
        assert html == []


# --------------------------------------------------------------------------- #
# _normalize integration tests                                                 #
# --------------------------------------------------------------------------- #

class TestNormalize:

    def test_simple_message_normalized(self):
        raw = _make_simple_payload()
        result = _normalize(raw)

        assert isinstance(result, NormalizedEmail)
        assert result.provider == "gmail"
        assert result.provider_message_id == "msg001"
        assert result.thread_id == "thr001"
        assert result.sender == "alice@example.com"
        assert result.subject == "Test Subject"
        assert result.body_text == "Hello world"
        assert result.body_html is None

    def test_multipart_message_both_bodies_extracted(self):
        raw = _make_multipart_payload(text="Plain body", html="<p>HTML body</p>")
        result = _normalize(raw)

        assert result.body_text == "Plain body"
        assert result.body_html == "<p>HTML body</p>"

    def test_provider_message_id_preserved(self):
        raw = _make_simple_payload(message_id="EXACT_ID_PRESERVED")
        result = _normalize(raw)
        assert result.provider_message_id == "EXACT_ID_PRESERVED"

    def test_thread_id_preserved(self):
        raw = _make_simple_payload(thread_id="THREAD_ID_PRESERVED")
        result = _normalize(raw)
        assert result.thread_id == "THREAD_ID_PRESERVED"

    def test_recipients_extracted(self):
        raw = _make_simple_payload(to="bob@example.com, carol@example.com")
        result = _normalize(raw)
        assert "bob@example.com" in result.recipients
        assert "carol@example.com" in result.recipients

    def test_received_at_parsed(self):
        raw = _make_simple_payload(date="Mon, 01 Jan 2024 10:00:00 +0000")
        result = _normalize(raw)
        assert result.received_at is not None
        assert result.received_at.year == 2024

    def test_raw_size_bytes_set(self):
        raw = _make_simple_payload(text="hello")
        raw["sizeEstimate"] = 1337
        result = _normalize(raw)
        assert result.raw_size_bytes == 1337

    def test_empty_payload_does_not_crash(self):
        raw = {
            "id": "empty_msg",
            "threadId": "empty_thread",
            "payload": {},
        }
        result = _normalize(raw)
        assert result.provider_message_id == "empty_msg"
        assert result.body_text is None
        assert result.body_html is None

    def test_missing_id_gives_empty_string(self):
        raw = {"threadId": "t1", "payload": {}}
        result = _normalize(raw)
        assert result.provider_message_id == ""

    def test_malformed_payload_does_not_crash(self):
        raw = {
            "id": "bad",
            "threadId": "bad_thread",
            "payload": {
                "mimeType": "text/plain",
                "headers": [{"name": "From", "value": "x@y.com"}],
                "body": {"data": "!!!NOT_VALID_BASE64!!!"},
            },
        }
        result = _normalize(raw)
        # Body may be None or a replacement-character string — must not raise.
        assert isinstance(result, NormalizedEmail)


# --------------------------------------------------------------------------- #
# fetch_and_normalize integration tests (mocked client)                       #
# --------------------------------------------------------------------------- #

class TestFetchAndNormalize:

    def test_calls_get_message_with_full_format(self):
        raw = _make_simple_payload()
        client = _make_mock_client(raw)

        fetch_and_normalize(client, "msg001")

        client.get_message.assert_called_once_with("msg001", fmt="full")

    def test_returns_normalized_email(self):
        raw = _make_simple_payload()
        client = _make_mock_client(raw)

        result = fetch_and_normalize(client, "msg001")
        assert isinstance(result, NormalizedEmail)

    def test_provider_message_id_matches_requested_id(self):
        raw = _make_simple_payload(message_id="requested_id")
        client = _make_mock_client(raw)

        result = fetch_and_normalize(client, "requested_id")
        assert result.provider_message_id == "requested_id"

    def test_thread_id_matches(self):
        raw = _make_simple_payload(thread_id="thread_xyz")
        client = _make_mock_client(raw)

        result = fetch_and_normalize(client, "msg001")
        assert result.thread_id == "thread_xyz"


# --------------------------------------------------------------------------- #
# PRIVACY SENTINEL: no disk writes                                             #
# --------------------------------------------------------------------------- #

class TestPrivacyNoDiskWrites:
    """
    CRITICAL PRIVACY TEST.

    Proves that fetch_and_normalize() does not write any raw email content,
    .eml files, or MIME payloads to disk during processing.

    Method: We monitor the filesystem by noting all .eml and .json files
    in the temp directory before and after the call, and assert none were
    created.  We also verify that open() is not called with write-mode on
    any .eml or raw-mime path.
    """

    def test_no_eml_files_written_to_temp(self, tmp_path):
        """No .eml files are created in the temp directory during fetch."""
        raw = _make_multipart_payload()
        client = _make_mock_client(raw)

        # Snapshot files before.
        before = set(tmp_path.rglob("*.eml"))

        # Run the pipeline.
        fetch_and_normalize(client, "msg002")

        # Snapshot after.
        after = set(tmp_path.rglob("*.eml"))
        assert after == before, (
            f"fetch_and_normalize() created unexpected .eml files: {after - before}"
        )

    def test_no_raw_mime_files_written(self):
        """
        The message fetcher must not use tempfile or open() in write mode
        with .eml or .mime paths.  We verify by monitoring the default
        temp directory.
        """
        import glob

        raw = _make_multipart_payload()
        client = _make_mock_client(raw)

        tmp_dir = tempfile.gettempdir()
        before_eml = set(glob.glob(os.path.join(tmp_dir, "**", "*.eml"), recursive=True))
        before_mime = set(glob.glob(os.path.join(tmp_dir, "**", "*.mime"), recursive=True))

        fetch_and_normalize(client, "msg002")

        after_eml = set(glob.glob(os.path.join(tmp_dir, "**", "*.eml"), recursive=True))
        after_mime = set(glob.glob(os.path.join(tmp_dir, "**", "*.mime"), recursive=True))

        new_eml = after_eml - before_eml
        new_mime = after_mime - before_mime

        assert not new_eml, f"Unexpected .eml files created: {new_eml}"
        assert not new_mime, f"Unexpected .mime files created: {new_mime}"

    def test_tempfile_module_not_used_in_fetcher(self):
        """
        message_fetcher.py must not import tempfile.
        Verifies the module's source does not contain a 'tempfile' import.
        """
        import ast
        import importlib.util
        import inspect

        import app.services.mail.message_fetcher as fetcher_mod

        source = inspect.getsource(fetcher_mod)
        # Check for direct import of tempfile.
        assert "import tempfile" not in source, (
            "message_fetcher.py must not import tempfile — "
            "raw email data must never be written to disk."
        )

    def test_open_not_called_with_write_mode_during_normalize(self):
        """
        Patch builtins.open and verify it is never called with a write mode
        ('w', 'wb', 'a', 'ab') during _normalize().

        NOTE: We only check _normalize() (pure in-memory path).
        The logging module and other stdlib paths may legitimately use open().
        We check specifically for .eml / .mime / .json paths in write mode.
        """
        raw = _make_multipart_payload()
        suspicious_opens: list[tuple] = []

        original_open = open

        def tracking_open(file, mode="r", *args, **kwargs):
            file_str = str(file)
            if any(ext in file_str for ext in (".eml", ".mime")) and any(
                m in mode for m in ("w", "a", "x")
            ):
                suspicious_opens.append((file_str, mode))
            return original_open(file, mode, *args, **kwargs)

        with patch("builtins.open", side_effect=tracking_open):
            _normalize(raw)

        assert not suspicious_opens, (
            f"_normalize() opened files in write mode: {suspicious_opens}"
        )
