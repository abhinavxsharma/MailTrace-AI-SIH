"""
Tests for header_parser (forensics.headers.parser).

Covers:
- Case-insensitivity
- Repeated Received headers preserved in order
- Repeated identity headers preserved
- Folded headers unfolded and normalized
- Preserved original values vs normalized values
- Authentication-Results parsed as data only
- ReceivedHop partial parsing and resilience on unusual headers
"""

from __future__ import annotations

from datetime import datetime, timezone

from forensics.email_parser.models import ParsedHeader, ReceivedHop
from forensics.headers.parser import parse_headers, parse_received_hop, unfold_header


# --------------------------------------------------------------------------- #
# Unfolding Tests                                                             #
# --------------------------------------------------------------------------- #

class TestUnfoldHeader:

    def test_single_line_unfolded_unchanged(self):
        assert unfold_header("Simple Value") == "Simple Value"

    def test_crlf_folding_unfolded(self):
        raw = "Line 1\r\n    Line 2\r\n\tLine 3"
        assert unfold_header(raw) == "Line 1 Line 2 Line 3"

    def test_lf_only_folding_unfolded(self):
        raw = "Part 1\n  Part 2"
        assert unfold_header(raw) == "Part 1 Part 2"

    def test_leading_trailing_whitespace_stripped(self):
        assert unfold_header("  padded string  ") == "padded string"

    def test_empty_string(self):
        assert unfold_header("") == ""


# --------------------------------------------------------------------------- #
# Header Parsing Tests                                                        #
# --------------------------------------------------------------------------- #

class TestHeaderParsing:

    def test_preserves_original_and_normalized_values(self):
        headers_input = [
            ("Subject", "  Important\r\n Notice  "),
        ]
        parsed = parse_headers(headers_input)
        assert len(parsed) == 1
        assert parsed[0].name == "Subject"
        assert parsed[0].original_value == "  Important\r\n Notice  "
        assert parsed[0].normalized_value == "Important Notice"

    def test_preserves_repeated_headers(self):
        headers_input = [
            ("Received", "from mail-a.example.com; Wed, 01 Jan 2024 10:00:00 +0000"),
            ("Received", "from mail-b.example.com; Wed, 01 Jan 2024 10:01:00 +0000"),
        ]
        parsed = parse_headers(headers_input)
        assert len(parsed) == 2
        assert parsed[0].normalized_value.startswith("from mail-a")
        assert parsed[1].normalized_value.startswith("from mail-b")

    def test_preserves_repeated_identity_headers(self):
        headers_input = [
            ("From", "attacker@evil.com"),
            ("From", "ceo@company.com"),
        ]
        parsed = parse_headers(headers_input)
        assert len(parsed) == 2
        assert parsed[0].normalized_value == "attacker@evil.com"
        assert parsed[1].normalized_value == "ceo@company.com"

    def test_authentication_results_parsed_as_data_only(self):
        auth_header = (
            "Authentication-Results",
            "mx.google.com; dkim=pass header.i=@example.com; spf=pass (google.com: domain of sender@example.com designates 192.0.2.1 as permitted sender) smtp.mailfrom=sender@example.com; dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=example.com",
        )
        parsed = parse_headers([auth_header])
        assert len(parsed) == 1
        assert parsed[0].name == "Authentication-Results"
        assert "dkim=pass" in parsed[0].normalized_value
        assert "spf=pass" in parsed[0].normalized_value
        assert "dmarc=pass" in parsed[0].normalized_value
        # Confirms: stored as raw data only, no verification logic executed in Chunk 2

    def test_dict_input_parsed(self):
        d = {"from": "alice@example.com", "to": "bob@example.com"}
        parsed = parse_headers(d)
        names = [h.name for h in parsed]
        assert "from" in names
        assert "to" in names


# --------------------------------------------------------------------------- #
# Received Hop Parsing Tests                                                   #
# --------------------------------------------------------------------------- #

class TestReceivedHopParsing:

    def test_standard_received_hop(self):
        raw = (
            "from mail.example.com (mail.example.com [192.0.2.1])\r\n"
            "    by mx.google.com with ESMTPS id abc123xyz\r\n"
            "    for <recipient@example.com>;\r\n"
            "    Wed, 18 Sep 2024 10:00:00 -0700"
        )
        hop = parse_received_hop(raw)

        assert isinstance(hop, ReceivedHop)
        assert hop.from_host is not None
        assert "mail.example.com" in hop.from_host
        assert hop.by_host is not None
        assert "mx.google.com" in hop.by_host
        assert hop.protocol == "ESMTPS"
        assert hop.id == "abc123xyz"
        assert hop.for_recipient == "<recipient@example.com>"
        assert hop.timestamp is not None
        assert hop.timestamp.tzinfo == timezone.utc
        assert hop.timestamp.year == 2024
        assert hop.timestamp.month == 9
        assert hop.timestamp.day == 18

    def test_partial_received_hop_missing_optional_clauses(self):
        # Hop with only by, with, and id (e.g. internal hop)
        raw = "by 2002:a05:6808:140d with SMTP id y13csp1234567oij; Wed, 18 Sep 2024 10:00:01 -0700"
        hop = parse_received_hop(raw)

        assert hop.from_host is None
        assert hop.by_host == "2002:a05:6808:140d"
        assert hop.protocol == "SMTP"
        assert hop.id == "y13csp1234567oij"
        assert hop.for_recipient is None
        assert hop.timestamp is not None

    def test_unusual_received_header_does_not_crash(self):
        # Malformed / completely unexpected format
        raw = "completely bizarre received header with no standard clauses"
        hop = parse_received_hop(raw)

        assert isinstance(hop, ReceivedHop)
        assert hop.original_value == raw
        assert hop.from_host is None
        assert hop.by_host is None
        assert hop.timestamp is None

    def test_received_hop_without_timestamp(self):
        raw = "from mail.sender.com by mx.receiver.com with ESMTP"
        hop = parse_received_hop(raw)

        assert hop.from_host is not None
        assert "mail.sender.com" in hop.from_host
        assert hop.by_host is not None
        assert "mx.receiver.com" in hop.by_host
        assert hop.timestamp is None
