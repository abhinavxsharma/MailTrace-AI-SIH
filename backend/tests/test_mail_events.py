"""Tests for Part 5 Mail Event Ingestion Gateway and Idempotency."""

import asyncio
import json
import unittest
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlparse

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.db.database import Base, init_db
from backend.app.db.session import get_db
from backend.app.main import app
from backend.app.schemas.analysis import NormalizedEmail
from backend.app.schemas.mail_event import MailEventStatus, MailEventType
from backend.app.services.provider_client import MailProviderClient


class DummyProviderClient(MailProviderClient):
    """Test stub implementing the MailProviderClient interface."""

    def fetch_message(
        self,
        provider_message_id: str,
        account_email: Optional[str] = None,
    ) -> NormalizedEmail:
        return NormalizedEmail(
            provider="gmail",
            provider_message_id=provider_message_id,
            sender="external@example.com",
            recipient=account_email or "user@mailtrace.ai",
            subject="Test Message",
            body="Test Content",
        )


class MailEventsTestCase(unittest.TestCase):
    """Test suite for Part 5 Mail Event Ingestion Gateway."""

    @classmethod
    def setUpClass(cls) -> None:
        """Set up an isolated in-memory SQLite database shared across test threads."""
        cls.test_engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        cls.TestingSessionLocal = sessionmaker(
            autocommit=False,
            autoflush=False,
            bind=cls.test_engine,
        )

        def override_get_db():
            db = cls.TestingSessionLocal()
            try:
                yield db
            finally:
                db.close()

        app.dependency_overrides[get_db] = override_get_db

    @classmethod
    def tearDownClass(cls) -> None:
        """Clear dependency overrides."""
        app.dependency_overrides.clear()

    def setUp(self) -> None:
        """Re-create clean tables for each test and register a test mailbox."""
        Base.metadata.drop_all(bind=self.test_engine)
        init_db(engine=self.test_engine)

        # Register default test mailbox
        self.request(
            "POST",
            "/api/mailboxes",
            {
                "provider": "gmail",
                "account_email": "analyst@mailtrace.ai",
                "status": "CONNECTED",
            },
        )

    def tearDown(self) -> None:
        """Drop tables after each test."""
        Base.metadata.drop_all(bind=self.test_engine)

    def request(
        self,
        method: str,
        url: str,
        data: Optional[Dict[str, Any]] = None,
    ) -> Tuple[int, Any]:
        """Perform an HTTP request directly against the FastAPI ASGI app."""
        parsed = urlparse(url)
        path = parsed.path
        query_string = parsed.query.encode("utf-8")
        body_bytes = json.dumps(data).encode("utf-8") if data is not None else b""

        headers = [(b"host", b"testserver")]
        if data is not None:
            headers.append((b"content-type", b"application/json"))

        scope = {
            "type": "http",
            "http_version": "1.1",
            "method": method.upper(),
            "path": path,
            "raw_path": path.encode("utf-8"),
            "query_string": query_string,
            "headers": headers,
            "client": ("127.0.0.1", 12345),
            "server": ("127.0.0.1", 80),
            "scheme": "http",
        }

        response_body = []
        status_code = 500

        async def receive():
            return {"type": "http.request", "body": body_bytes, "more_body": False}

        async def send(message):
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = message["status"]
            elif message["type"] == "http.response.body":
                response_body.append(message.get("body", b""))

        asyncio.run(app(scope, receive, send))

        raw_content = b"".join(response_body).decode("utf-8")
        try:
            parsed_json = json.loads(raw_content) if raw_content else None
        except json.JSONDecodeError:
            parsed_json = raw_content

        return status_code, parsed_json

    # 1. Valid NEW_MESSAGE accepted
    def test_valid_new_message_accepted(self) -> None:
        payload = {
            "provider": "gmail",
            "account_email": "analyst@mailtrace.ai",
            "provider_message_id": "gmail-msg-001",
            "thread_id": "thread-001",
            "event_type": "NEW_MESSAGE",
            "received_at": "2026-09-19T10:00:00Z",
        }
        status_code, body = self.request("POST", "/api/mail/events", payload)
        self.assertEqual(status_code, 200)
        self.assertEqual(body["status"], MailEventStatus.ACCEPTED.value)
        self.assertEqual(body["provider"], "gmail")
        self.assertEqual(body["provider_message_id"], "gmail-msg-001")
        self.assertTrue(body["case_id"].startswith("case_"))
        self.assertIsNotNone(body["mailbox_id"])

    # 2. Invalid provider rejected
    def test_invalid_provider_rejected(self) -> None:
        payload = {
            "provider": "",
            "account_email": "analyst@mailtrace.ai",
            "provider_message_id": "msg-002",
            "event_type": "NEW_MESSAGE",
        }
        status_code, _ = self.request("POST", "/api/mail/events", payload)
        self.assertEqual(status_code, 422)

    # 3. Invalid provider_message_id rejected
    def test_invalid_provider_message_id_rejected(self) -> None:
        payload = {
            "provider": "gmail",
            "account_email": "analyst@mailtrace.ai",
            "provider_message_id": "",
            "event_type": "NEW_MESSAGE",
        }
        status_code, _ = self.request("POST", "/api/mail/events", payload)
        self.assertEqual(status_code, 422)

    # 4. Invalid event_type rejected
    def test_invalid_event_type_rejected(self) -> None:
        payload = {
            "provider": "gmail",
            "account_email": "analyst@mailtrace.ai",
            "provider_message_id": "msg-004",
            "event_type": "UNKNOWN_ACTION",
        }
        status_code, _ = self.request("POST", "/api/mail/events", payload)
        self.assertEqual(status_code, 422)

    # 5. Nonexistent mailbox handled correctly
    def test_nonexistent_mailbox_rejected(self) -> None:
        payload = {
            "provider": "gmail",
            "account_email": "unregistered@domain.com",
            "provider_message_id": "msg-005",
            "event_type": "NEW_MESSAGE",
        }
        status_code, body = self.request("POST", "/api/mail/events", payload)
        self.assertEqual(status_code, 404)
        self.assertIn("does not exist", body["detail"])

    # 6. Duplicate event detected
    def test_duplicate_event_detected(self) -> None:
        payload = {
            "provider": "gmail",
            "account_email": "analyst@mailtrace.ai",
            "provider_message_id": "idempotent-msg-999",
            "event_type": "NEW_MESSAGE",
        }
        # First delivery
        status_code_1, body_1 = self.request("POST", "/api/mail/events", payload)
        self.assertEqual(status_code_1, 200)
        self.assertEqual(body_1["status"], MailEventStatus.ACCEPTED.value)
        case_id = body_1["case_id"]

        # Duplicate delivery
        status_code_2, body_2 = self.request("POST", "/api/mail/events", payload)
        self.assertEqual(status_code_2, 200)
        self.assertEqual(body_2["status"], MailEventStatus.DUPLICATE.value)
        self.assertEqual(body_2["case_id"], case_id)
        self.assertIn("Duplicate", body_2["message"])

    # 7. Existing case reused
    def test_existing_case_reused(self) -> None:
        payload = {
            "provider": "gmail",
            "account_email": "analyst@mailtrace.ai",
            "provider_message_id": "reuse-case-msg",
            "event_type": "NEW_MESSAGE",
        }
        _, first = self.request("POST", "/api/mail/events", payload)
        _, second = self.request("POST", "/api/mail/events", payload)

        self.assertEqual(first["case_id"], second["case_id"])

    # 8. Event audit created
    def test_event_audit_created(self) -> None:
        payload = {
            "provider": "gmail",
            "account_email": "analyst@mailtrace.ai",
            "provider_message_id": "audit-track-msg",
            "event_type": "NEW_MESSAGE",
        }
        _, resp = self.request("POST", "/api/mail/events", payload)
        case_id = resp["case_id"]

        # Send duplicate to trigger DUPLICATE_MAIL_EVENT
        self.request("POST", "/api/mail/events", payload)

        status_code, audit_events = self.request("GET", f"/api/cases/{case_id}/audit")
        self.assertEqual(status_code, 200)
        event_types = [e["event_type"] for e in audit_events]
        self.assertIn("MAIL_EVENT_RECEIVED", event_types)
        self.assertIn("DUPLICATE_MAIL_EVENT", event_types)

    # 9. No file upload required
    def test_no_file_upload_required(self) -> None:
        payload = {
            "provider": "gmail",
            "account_email": "analyst@mailtrace.ai",
            "provider_message_id": "in-memory-event-test",
            "event_type": "NEW_MESSAGE",
        }
        status_code, body = self.request("POST", "/api/mail/events", payload)
        self.assertEqual(status_code, 200)
        self.assertEqual(body["status"], "accepted")

    # 10. MailProviderClient contract interface test
    def test_mail_provider_client_contract(self) -> None:
        client = DummyProviderClient()
        normalized = client.fetch_message("msg-abc", "analyst@mailtrace.ai")
        self.assertIsInstance(normalized, NormalizedEmail)
        self.assertEqual(normalized.provider_message_id, "msg-abc")
        self.assertEqual(normalized.recipient, "analyst@mailtrace.ai")


if __name__ == "__main__":
    unittest.main()
