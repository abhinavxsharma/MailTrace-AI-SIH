"""
Tests for email_parser (forensics.email_parser).

Covers:
- Address parsing (plain, display name, quoted, multiple, malformed, normalization)
- URL extraction (plain text, HTML, ports, paths, queries, deduplication)
- Email parsing from NormalizedEmail and in-memory MIME
- Plain text, HTML, multipart/alternative, multipart/mixed, nested multipart
- Missing bodies, missing optional headers, malformed optional data
- Attachment metadata extraction without disk writes

CRITICAL PRIVACY GUARANTEE:
All fixtures are created entirely in memory. No .eml files or attachments
are written to disk.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app.services.mail.models import NormalizedEmail
from forensics.email_parser import (
    AttachmentMetadata,
    ExtractedUrl,
    ParsedAddress,
    ParsedEmail,
    extract_urls,
    parse_address,
    parse_addresses,
    parse_email,
)


# --------------------------------------------------------------------------- #
# Address Parsing Tests                                                       #
# --------------------------------------------------------------------------- #

class TestAddressParser:

    def test_plain_address(self):
        result = parse_address("alice@example.com")
        assert result.email == "alice@example.com"
        assert result.local_part == "alice"
        assert result.domain == "example.com"
        assert result.display_name == ""
        assert result.original_value == "alice@example.com"

    def test_display_name(self):
        result = parse_address("Alice Smith <alice@example.com>")
        assert result.email == "alice@example.com"
        assert result.local_part == "alice"
        assert result.domain == "example.com"
        assert result.display_name == "Alice Smith"

    def test_quoted_display_name(self):
        result = parse_address('"Smith, Alice" <alice@example.com>')
        assert result.email == "alice@example.com"
        assert result.local_part == "alice"
        assert result.domain == "example.com"
        assert result.display_name == "Smith, Alice"

    def test_multiple_addresses(self):
        raw = "Alice <alice@example.com>, Bob <bob@example.com>, carol@example.org"
        results = parse_addresses(raw)
        assert len(results) == 3
        assert results[0].email == "alice@example.com"
        assert results[0].display_name == "Alice"
        assert results[1].email == "bob@example.com"
        assert results[1].display_name == "Bob"
        assert results[2].email == "carol@example.org"
        assert results[2].display_name == ""

    def test_address_normalization_lowercases(self):
        result = parse_address("John Doe <JOHN.DOE@EXAMPLE.COM>")
        assert result.email == "john.doe@example.com"
        assert result.domain == "example.com"
        assert result.local_part == "john.doe"
        assert result.display_name == "John Doe"

    def test_malformed_address_does_not_crash(self):
        # Bare string with no @
        result = parse_address("not-an-email")
        assert result.email == "not-an-email"
        assert result.domain == ""
        assert result.local_part == "not-an-email"

        # Empty string
        empty = parse_address("")
        assert empty.email == ""
        assert empty.domain == ""

        # Only domain
        at_only = parse_address("@example.com")
        assert at_only.domain == "example.com"
        assert at_only.local_part == ""


# --------------------------------------------------------------------------- #
# URL Extraction Tests                                                        #
# --------------------------------------------------------------------------- #

class TestUrlExtraction:

    def test_extract_from_plain_text(self):
        text = "Check this out: https://example.com/login?ref=email and http://test.org:8080/path"
        urls = extract_urls(text, None)
        assert len(urls) == 2

        assert urls[0].original_url == "https://example.com/login?ref=email"
        assert urls[0].scheme == "https"
        assert urls[0].host == "example.com"
        assert urls[0].path == "/login"
        assert urls[0].query == "ref=email"
        assert urls[0].port is None

        assert urls[1].original_url == "http://test.org:8080/path"
        assert urls[1].scheme == "http"
        assert urls[1].host == "test.org"
        assert urls[1].port == 8080
        assert urls[1].path == "/path"

    def test_extract_from_html(self):
        html = '<p>Click <a href="https://secure.example.com/account">here</a> or visit https://plain.example.com</p>'
        urls = extract_urls(None, html)
        hosts = [u.host for u in urls]
        assert "secure.example.com" in hosts
        assert "plain.example.com" in hosts

    def test_deduplication_preserves_order(self):
        text = "https://example.com https://other.com https://example.com"
        urls = extract_urls(text, None)
        assert len(urls) == 2
        assert urls[0].host == "example.com"
        assert urls[1].host == "other.com"

    def test_trailing_punctuation_stripped(self):
        text = "Visit https://example.com/page. Also see (https://example.com/doc)!"
        urls = extract_urls(text, None)
        assert urls[0].original_url == "https://example.com/page"
        assert urls[1].original_url == "https://example.com/doc"

    def test_empty_bodies_return_empty_list(self):
        assert extract_urls(None, None) == []
        assert extract_urls("", "") == []


# --------------------------------------------------------------------------- #
# Email Parser Tests (from NormalizedEmail & MIME)                             #
# --------------------------------------------------------------------------- #

class TestEmailParser:

    def test_parse_from_normalized_email(self):
        dt = datetime(2024, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        norm = NormalizedEmail(
            provider="gmail",
            provider_message_id="msg123",
            thread_id="thread456",
            sender="Alice <alice@example.com>",
            recipients=["bob@example.com"],
            subject="Test Subject",
            body_text="Hello https://example.com",
            body_html="<p>Hello <a href='https://example.com'>link</a></p>",
            headers={
                "from": "Alice <alice@example.com>",
                "to": "bob@example.com",
                "message-id": "<123@example.com>",
                "date": "Sat, 01 Jun 2024 12:00:00 +0000",
            },
            received_at=dt,
        )

        parsed = parse_email(norm)

        assert isinstance(parsed, ParsedEmail)
        assert parsed.message_id == "msg123"
        assert parsed.thread_id == "thread456"
        assert parsed.from_address is not None
        assert parsed.from_address.email == "alice@example.com"
        assert parsed.from_address.display_name == "Alice"
        assert len(parsed.to_addresses) == 1
        assert parsed.to_addresses[0].email == "bob@example.com"
        assert parsed.subject == "Test Subject"
        assert parsed.message_id_header == "<123@example.com>"
        assert parsed.date == dt
        assert len(parsed.extracted_urls) == 1
        assert parsed.extracted_urls[0].host == "example.com"

    def test_parse_plain_text_mime(self):
        raw = (
            "From: sender@example.com\r\n"
            "To: recipient@example.com\r\n"
            "Subject: Plain email\r\n"
            "Date: Sun, 02 Jun 2024 10:00:00 +0000\r\n"
            "Message-ID: <plain@example.com>\r\n"
            "Content-Type: text/plain; charset=utf-8\r\n"
            "\r\n"
            "This is a simple plain text body.\r\n"
        )
        parsed = parse_email(raw)
        assert parsed.subject == "Plain email"
        assert parsed.body_text == "This is a simple plain text body.\r\n"
        assert parsed.body_html is None
        assert parsed.from_address is not None
        assert parsed.from_address.email == "sender@example.com"

    def test_parse_html_mime(self):
        raw = (
            "From: sender@example.com\r\n"
            "To: recipient@example.com\r\n"
            "Subject: HTML email\r\n"
            "Content-Type: text/html; charset=utf-8\r\n"
            "\r\n"
            "<html><body><h1>Hello HTML</h1></body></html>\r\n"
        )
        parsed = parse_email(raw)
        assert parsed.body_html == "<html><body><h1>Hello HTML</h1></body></html>\r\n"
        assert parsed.body_text is None

    def test_parse_multipart_alternative(self):
        raw = (
            "From: alice@example.com\r\n"
            "To: bob@example.com\r\n"
            "Subject: Multi Alt\r\n"
            "MIME-Version: 1.0\r\n"
            "Content-Type: multipart/alternative; boundary=\"boundary42\"\r\n"
            "\r\n"
            "--boundary42\r\n"
            "Content-Type: text/plain; charset=utf-8\r\n"
            "\r\n"
            "Plain text content.\r\n"
            "--boundary42\r\n"
            "Content-Type: text/html; charset=utf-8\r\n"
            "\r\n"
            "<b>HTML content.</b>\r\n"
            "--boundary42--\r\n"
        )
        parsed = parse_email(raw)
        assert parsed.body_text == "Plain text content."
        assert parsed.body_html == "<b>HTML content.</b>"
        assert len(parsed.attachments) == 0

    def test_parse_multipart_mixed_with_attachment_metadata(self):
        raw = (
            "From: sender@example.com\r\n"
            "To: recipient@example.com\r\n"
            "Subject: Email with attachment\r\n"
            "MIME-Version: 1.0\r\n"
            "Content-Type: multipart/mixed; boundary=\"mixed_bnd\"\r\n"
            "\r\n"
            "--mixed_bnd\r\n"
            "Content-Type: text/plain\r\n"
            "\r\n"
            "Please see attached invoice.\r\n"
            "--mixed_bnd\r\n"
            "Content-Type: application/pdf; name=\"invoice.pdf\"\r\n"
            "Content-Disposition: attachment; filename=\"invoice.pdf\"\r\n"
            "Content-ID: <inv123@example.com>\r\n"
            "Content-Transfer-Encoding: base64\r\n"
            "\r\n"
            "JVBERi0xLjQKJeLjz9M=\r\n"
            "--mixed_bnd--\r\n"
        )
        parsed = parse_email(raw)
        assert parsed.body_text == "Please see attached invoice."
        assert len(parsed.attachments) == 1

        att = parsed.attachments[0]
        assert att.filename == "invoice.pdf"
        assert att.content_type == "application/pdf"
        assert att.disposition == "attachment"
        assert att.content_id == "<inv123@example.com>"
        assert att.size is not None
        assert att.size > 0

    def test_parse_nested_multipart(self):
        raw = (
            "From: sender@example.com\r\n"
            "To: recipient@example.com\r\n"
            "Subject: Nested multipart\r\n"
            "MIME-Version: 1.0\r\n"
            "Content-Type: multipart/mixed; boundary=\"outer_bnd\"\r\n"
            "\r\n"
            "--outer_bnd\r\n"
            "Content-Type: multipart/alternative; boundary=\"inner_bnd\"\r\n"
            "\r\n"
            "--inner_bnd\r\n"
            "Content-Type: text/plain\r\n"
            "\r\n"
            "Inner text body.\r\n"
            "--inner_bnd\r\n"
            "Content-Type: text/html\r\n"
            "\r\n"
            "<p>Inner HTML body.</p>\r\n"
            "--inner_bnd--\r\n"
            "--outer_bnd\r\n"
            "Content-Type: text/csv; name=\"data.csv\"\r\n"
            "Content-Disposition: attachment; filename=\"data.csv\"\r\n"
            "\r\n"
            "col1,col2\r\nval1,val2\r\n"
            "--outer_bnd--\r\n"
        )
        parsed = parse_email(raw)
        assert parsed.body_text == "Inner text body."
        assert parsed.body_html == "<p>Inner HTML body.</p>"
        assert len(parsed.attachments) == 1
        assert parsed.attachments[0].filename == "data.csv"
        assert parsed.attachments[0].content_type == "text/csv"

    def test_missing_body_and_missing_optional_headers(self):
        raw = "From: sender@example.com\r\nSubject: No body\r\n\r\n"
        parsed = parse_email(raw)
        assert parsed.body_text is None or parsed.body_text == ""
        assert parsed.body_html is None
        assert parsed.to_addresses == []
        assert parsed.cc_addresses == []
        assert parsed.date is None
        assert parsed.message_id_header is None

    def test_malformed_optional_data_does_not_crash(self):
        raw = (
            "From: sender@example.com\r\n"
            "Date: not-a-real-date-at-all\r\n"
            "Message-ID: malformed-no-brackets\r\n"
            "References: not a valid ref\r\n"
            "\r\n"
            "Hello world\r\n"
        )
        parsed = parse_email(raw)
        assert parsed.date is None  # unparseable date handled gracefully
        assert parsed.message_id_header == "malformed-no-brackets"
        assert parsed.body_text == "Hello world\r\n"


# --------------------------------------------------------------------------- #
# ParsedEmail Helper Methods Tests                                            #
# --------------------------------------------------------------------------- #

class TestParsedEmailHelpers:

    def test_case_insensitive_header_lookup(self):
        norm = NormalizedEmail(
            provider="gmail",
            provider_message_id="msg1",
            thread_id="t1",
            sender="a@b.com",
            headers={
                "subject": "Important",
                "x-custom-header": "CustomValue",
            },
        )
        parsed = parse_email(norm)
        assert parsed.get_header("subject") == "Important"
        assert parsed.get_header("SUBJECT") == "Important"
        assert parsed.get_header("Subject") == "Important"
        assert parsed.get_header("X-Custom-Header") == "CustomValue"
        assert parsed.get_header("nonexistent") is None

    def test_get_headers_returns_all_matches(self):
        raw = (
            "From: a@b.com\r\n"
            "X-Tag: tag1\r\n"
            "X-Tag: tag2\r\n"
            "\r\n"
            "body\r\n"
        )
        parsed = parse_email(raw)
        assert parsed.get_headers("x-tag") == ["tag1", "tag2"]
        assert parsed.get_headers("X-TAG") == ["tag1", "tag2"]
