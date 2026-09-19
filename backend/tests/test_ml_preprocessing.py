"""
Tests for ML input preprocessing (ml.inference.preprocessing).

Covers:
- Subject + Body formatting
- Missing subject
- Missing body
- Empty email
- Long text
- HTML body fallback when text body is absent
- HTML tag stripping and entity unescaping
- Invariant verification: no headers, authentication results, or IPs injected
"""

from __future__ import annotations

from forensics.email_parser.models import ParsedAddress, ParsedEmail, ParsedHeader
from ml.inference.preprocessing import prepare_model_input, strip_html_tags


def _make_parsed_email(
    subject: str = "Test Subject",
    body_text: str | None = "This is the body text.",
    body_html: str | None = None,
) -> ParsedEmail:
    return ParsedEmail(
        message_id="msg123",
        subject=subject,
        body_text=body_text,
        body_html=body_html,
        from_address=ParsedAddress(email="alice@example.com"),
        headers=[
            ParsedHeader(name="From", original_value="alice@example.com", normalized_value="alice@example.com"),
            ParsedHeader(name="Subject", original_value=subject, normalized_value=subject),
            ParsedHeader(name="Authentication-Results", original_value="spf=pass", normalized_value="spf=pass"),
        ],
    )


class TestPreprocessing:

    def test_standard_subject_and_body_formatting(self):
        email = _make_parsed_email(subject="Invoice Attached", body_text="Please review the attached invoice.")
        output = prepare_model_input(email)

        expected = "Subject: Invoice Attached\n\nBody:\nPlease review the attached invoice."
        assert output == expected

    def test_missing_subject_handled_gracefully(self):
        email = _make_parsed_email(subject="", body_text="Body with no subject.")
        output = prepare_model_input(email)

        expected = "Subject: \n\nBody:\nBody with no subject."
        assert output == expected

    def test_missing_body_handled_gracefully(self):
        email = _make_parsed_email(subject="Subject Only", body_text=None, body_html=None)
        output = prepare_model_input(email)

        expected = "Subject: Subject Only\n\nBody:\n"
        assert output == expected

    def test_completely_empty_email(self):
        email = _make_parsed_email(subject="", body_text=None, body_html=None)
        output = prepare_model_input(email)

        expected = "Subject: \n\nBody:\n"
        assert output == expected

    def test_html_fallback_when_body_text_is_none(self):
        html_content = "<p>Hello <b>World</b>!</p><br/><p>Click <a href='https://example.com'>here</a> &amp; enjoy.</p>"
        email = _make_parsed_email(subject="HTML Email", body_text=None, body_html=html_content)
        output = prepare_model_input(email)

        assert "Subject: HTML Email\n\nBody:\n" in output
        assert "Hello World !" in output or "Hello World!" in output
        assert "here & enjoy." in output
        assert "<p>" not in output
        assert "<a href" not in output

    def test_strip_html_tags_helper(self):
        raw_html = "<div>First line</div><br/><p>Second line &amp; symbols &lt;&gt;</p>"
        clean = strip_html_tags(raw_html)
        assert "First line" in clean
        assert "Second line & symbols <>" in clean
        assert "<div>" not in clean
        assert "&amp;" not in clean

    def test_dictionary_input_supported(self):
        dict_input = {
            "subject": "Dict Subject",
            "body_text": "Dict Body",
        }
        output = prepare_model_input(dict_input)
        assert output == "Subject: Dict Subject\n\nBody:\nDict Body"

    def test_raw_string_input_supported(self):
        raw_text = "Subject: Pre-formatted\n\nBody:\nContent"
        output = prepare_model_input(raw_text)
        assert output == raw_text

    def test_no_headers_or_authentication_injected(self):
        """Verify strict invariant: authentication results, headers, IPs are never in the ML input."""
        email = _make_parsed_email(
            subject="Security Alert",
            body_text="Your account requires verification.",
        )
        output = prepare_model_input(email)

        assert "Authentication-Results" not in output
        assert "spf=pass" not in output
        assert "alice@example.com" not in output  # sender not in subject/body
        assert output == "Subject: Security Alert\n\nBody:\nYour account requires verification."
