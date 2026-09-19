"""
Tests for NormalizedEmail model (app.services.mail.models).

No credentials, internet access, or external services required.
"""

from __future__ import annotations

import pytest
from datetime import datetime, timezone

from pydantic import ValidationError

from app.services.mail.models import NormalizedEmail


# --------------------------------------------------------------------------- #
# Helpers                                                                      #
# --------------------------------------------------------------------------- #

def _minimal() -> dict:
    """Minimal valid NormalizedEmail constructor kwargs."""
    return {
        "provider_message_id": "abc123",
        "thread_id": "thread456",
        "sender": "sender@example.com",
    }


# --------------------------------------------------------------------------- #
# Construction tests                                                           #
# --------------------------------------------------------------------------- #

class TestNormalizedEmailConstruction:

    def test_minimal_valid_construction(self):
        """NormalizedEmail can be built with only the required fields."""
        email = NormalizedEmail(**_minimal())
        assert email.provider_message_id == "abc123"
        assert email.thread_id == "thread456"
        assert email.sender == "sender@example.com"

    def test_default_provider_is_gmail(self):
        email = NormalizedEmail(**_minimal())
        assert email.provider == "gmail"

    def test_default_recipients_is_empty_list(self):
        email = NormalizedEmail(**_minimal())
        assert email.recipients == []

    def test_default_subject_is_empty_string(self):
        email = NormalizedEmail(**_minimal())
        assert email.subject == ""

    def test_default_body_text_is_none(self):
        email = NormalizedEmail(**_minimal())
        assert email.body_text is None

    def test_default_body_html_is_none(self):
        email = NormalizedEmail(**_minimal())
        assert email.body_html is None

    def test_default_headers_is_empty_dict(self):
        email = NormalizedEmail(**_minimal())
        assert email.headers == {}

    def test_default_received_at_is_none(self):
        email = NormalizedEmail(**_minimal())
        assert email.received_at is None

    def test_default_raw_size_bytes_is_none(self):
        email = NormalizedEmail(**_minimal())
        assert email.raw_size_bytes is None


# --------------------------------------------------------------------------- #
# Field population tests                                                       #
# --------------------------------------------------------------------------- #

class TestNormalizedEmailFields:

    def test_all_fields_populated(self):
        now = datetime(2024, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        email = NormalizedEmail(
            provider="gmail",
            provider_message_id="msgid-001",
            thread_id="threadid-001",
            sender="alice@example.com",
            recipients=["bob@example.com", "carol@example.com"],
            subject="Test email",
            body_text="Hello world",
            body_html="<p>Hello world</p>",
            headers={"from": "alice@example.com", "subject": "Test email"},
            received_at=now,
            raw_size_bytes=1024,
        )
        assert email.provider == "gmail"
        assert email.provider_message_id == "msgid-001"
        assert email.thread_id == "threadid-001"
        assert email.sender == "alice@example.com"
        assert email.recipients == ["bob@example.com", "carol@example.com"]
        assert email.subject == "Test email"
        assert email.body_text == "Hello world"
        assert email.body_html == "<p>Hello world</p>"
        assert email.headers["from"] == "alice@example.com"
        assert email.received_at == now
        assert email.raw_size_bytes == 1024

    def test_provider_message_id_preserved_exactly(self):
        """provider_message_id is stored exactly as provided (opaque string)."""
        raw_id = "17d3c8a7b2f1e0c4"
        email = NormalizedEmail(provider_message_id=raw_id, **{
            k: v for k, v in _minimal().items() if k != "provider_message_id"
        })
        assert email.provider_message_id == raw_id

    def test_thread_id_preserved_exactly(self):
        """thread_id is stored exactly as provided."""
        raw_thread = "17d3c8a7b2f1e0c4"
        email = NormalizedEmail(thread_id=raw_thread, **{
            k: v for k, v in _minimal().items() if k != "thread_id"
        })
        assert email.thread_id == raw_thread

    def test_received_at_accepts_utc_datetime(self):
        dt = datetime(2024, 1, 15, 10, 30, tzinfo=timezone.utc)
        email = NormalizedEmail(**_minimal(), received_at=dt)
        assert email.received_at == dt

    def test_received_at_accepts_none(self):
        email = NormalizedEmail(**_minimal(), received_at=None)
        assert email.received_at is None


# --------------------------------------------------------------------------- #
# Required field enforcement                                                   #
# --------------------------------------------------------------------------- #

class TestNormalizedEmailValidation:

    def test_missing_provider_message_id_raises(self):
        with pytest.raises(ValidationError) as exc_info:
            NormalizedEmail(thread_id="t1", sender="a@b.com")
        errors = exc_info.value.errors()
        assert any(e["loc"] == ("provider_message_id",) for e in errors)

    def test_missing_thread_id_raises(self):
        with pytest.raises(ValidationError) as exc_info:
            NormalizedEmail(provider_message_id="m1", sender="a@b.com")
        errors = exc_info.value.errors()
        assert any(e["loc"] == ("thread_id",) for e in errors)

    def test_missing_sender_raises(self):
        with pytest.raises(ValidationError) as exc_info:
            NormalizedEmail(provider_message_id="m1", thread_id="t1")
        errors = exc_info.value.errors()
        assert any(e["loc"] == ("sender",) for e in errors)


# --------------------------------------------------------------------------- #
# Immutability                                                                 #
# --------------------------------------------------------------------------- #

class TestNormalizedEmailImmutability:

    def test_model_is_frozen(self):
        """NormalizedEmail is frozen — direct field assignment must raise."""
        email = NormalizedEmail(**_minimal())
        with pytest.raises(Exception):
            email.subject = "tampered"  # type: ignore[misc]

    def test_model_copy_update_works(self):
        """model_copy(update=...) creates a new instance correctly."""
        email = NormalizedEmail(**_minimal())
        updated = email.model_copy(update={"subject": "updated subject"})
        assert updated.subject == "updated subject"
        assert email.subject == ""  # original unchanged
