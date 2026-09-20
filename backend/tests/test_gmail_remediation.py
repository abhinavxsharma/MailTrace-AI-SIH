"""
Tests for Real Gmail Remediation Actions (Chunk 3/5).

Validates:
1. Report Spam:
   - Success (modifies labels: add SPAM, remove INBOX)
   - Missing message (404)
   - Invalid mailbox (404)
   - Insufficient scope (403)
   - Provider failure (502)
2. Delete:
   - Success (safe trash operation -> TRASHED)
   - Missing message (404)
   - Invalid mailbox (404)
   - Insufficient scope (403)
   - Provider failure (502)
3. Block Sender:
   - Success (extracts sender, creates filter routing to trash)
   - Sender extraction verification
   - Invalid/missing sender address (400)
   - Filter idempotency (already blocked -> already_blocked: True, no duplicate filter created)
   - Insufficient scope (403)
   - Provider failure (502)
4. Token safety: Zero token leakage in responses or logs
"""

from __future__ import annotations

import asyncio
import json
import unittest
from typing import Any, Dict, Optional, Tuple
from unittest.mock import MagicMock, patch
from urllib.parse import urlparse
from googleapiclient.errors import HttpError
from httplib2 import Response
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.db.database import Base, init_db
from backend.app.db.session import get_db
from backend.app.main import app
from backend.app.models.enums import MailboxStatus
from backend.app.models.mailbox import Mailbox


def _make_http_error(status_code: int, reason: str = "Error", content: bytes = b"") -> HttpError:
    """Create a mock Google HttpError with status code, reason, and content."""
    resp = Response({"status": str(status_code), "reason": reason})
    return HttpError(resp=resp, content=content)


class TestGmailRemediation(unittest.TestCase):
    """Test suite for Gmail remediation actions (Report Spam, Delete, Block Sender)."""

    @classmethod
    def setUpClass(cls) -> None:
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
        app.dependency_overrides.clear()

    def setUp(self) -> None:
        Base.metadata.drop_all(bind=self.test_engine)
        init_db(engine=self.test_engine)

    def tearDown(self) -> None:
        Base.metadata.drop_all(bind=self.test_engine)

    def request(
        self,
        method: str,
        url: str,
        data: Optional[Dict[str, Any]] = None,
    ) -> Tuple[int, Any]:
        """Perform an HTTP request directly against the ASGI app."""
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

        body_raw = b"".join(response_body).decode("utf-8")
        try:
            return status_code, json.loads(body_raw)
        except json.JSONDecodeError:
            return status_code, body_raw

    def _seed_mailbox(self, provider: str = "gmail", email: str = "target.user@gmail.com") -> int:
        with self.TestingSessionLocal() as session:
            mailbox = Mailbox(
                provider=provider,
                account_email=email,
                status=MailboxStatus.CONNECTED.value,
            )
            session.add(mailbox)
            session.commit()
            return mailbox.id

    # =========================================================================
    # 1. REPORT SPAM TESTS
    # =========================================================================

    @patch("backend.app.services.gmail.client.TokenStore.get_credentials")
    @patch("backend.app.services.gmail.client.build_gmail_service")
    def test_report_spam_success(self, mock_build_svc: MagicMock, mock_get_creds: MagicMock) -> None:
        mailbox_id = self._seed_mailbox()
        mock_creds = MagicMock()
        mock_creds.scopes = ["https://www.googleapis.com/auth/gmail.modify"]
        mock_get_creds.return_value = mock_creds

        mock_svc = MagicMock()
        mock_messages = mock_svc.users.return_value.messages.return_value
        mock_messages.modify.return_value.execute.return_value = {
            "id": "msg_spam_1",
            "labelIds": ["SPAM"],
        }
        mock_build_svc.return_value = mock_svc

        status_code, body = self.request(
            "POST",
            f"/api/mailboxes/{mailbox_id}/messages/msg_spam_1/report-spam",
        )

        self.assertEqual(status_code, 200)
        self.assertTrue(body["success"])
        self.assertEqual(body["action"], "REPORT_SPAM")
        self.assertEqual(body["message_id"], "msg_spam_1")
        self.assertEqual(body["status"], "REPORTED")

        # Verify modify API was called with addLabelIds: ['SPAM'] and removeLabelIds: ['INBOX']
        mock_messages.modify.assert_called_once_with(
            userId="me",
            id="msg_spam_1",
            body={"addLabelIds": ["SPAM"], "removeLabelIds": ["INBOX"]},
        )

    def test_report_spam_invalid_mailbox_404(self) -> None:
        status_code, body = self.request(
            "POST",
            "/api/mailboxes/99999/messages/msg_spam_1/report-spam",
        )
        self.assertEqual(status_code, 404)
        self.assertIn("Mailbox not found", body["detail"])

    @patch("backend.app.services.gmail.client.TokenStore.get_credentials")
    @patch("backend.app.services.gmail.client.build_gmail_service")
    def test_report_spam_missing_message_404(self, mock_build_svc: MagicMock, mock_get_creds: MagicMock) -> None:
        mailbox_id = self._seed_mailbox()
        mock_creds = MagicMock()
        mock_creds.scopes = ["https://www.googleapis.com/auth/gmail.modify"]
        mock_get_creds.return_value = mock_creds

        mock_svc = MagicMock()
        mock_svc.users().messages().modify().execute.side_effect = _make_http_error(404, "Not Found")
        mock_build_svc.return_value = mock_svc

        status_code, body = self.request(
            "POST",
            f"/api/mailboxes/{mailbox_id}/messages/nonexistent_msg/report-spam",
        )
        self.assertEqual(status_code, 404)
        self.assertIn("not found", body["detail"])

    @patch("backend.app.services.gmail.client.TokenStore.get_credentials")
    def test_report_spam_insufficient_scope_403(self, mock_get_creds: MagicMock) -> None:
        mailbox_id = self._seed_mailbox()
        # Credentials only have readonly scope
        mock_creds = MagicMock()
        mock_creds.scopes = ["https://www.googleapis.com/auth/gmail.readonly"]
        mock_get_creds.return_value = mock_creds

        status_code, body = self.request(
            "POST",
            f"/api/mailboxes/{mailbox_id}/messages/msg_spam_1/report-spam",
        )
        self.assertEqual(status_code, 403)
        self.assertIn("Additional Gmail permission required", body["detail"])
        self.assertEqual(body["error"]["code"], "INSUFFICIENT_PERMISSIONS")

    @patch("backend.app.services.gmail.client.TokenStore.get_credentials")
    @patch("backend.app.services.gmail.client.build_gmail_service")
    def test_report_spam_provider_500_raises_502(self, mock_build_svc: MagicMock, mock_get_creds: MagicMock) -> None:
        mailbox_id = self._seed_mailbox()
        mock_creds = MagicMock()
        mock_creds.scopes = ["https://www.googleapis.com/auth/gmail.modify"]
        mock_get_creds.return_value = mock_creds

        mock_svc = MagicMock()
        mock_svc.users().messages().modify().execute.side_effect = _make_http_error(500, "Backend Error")
        mock_build_svc.return_value = mock_svc

        status_code, body = self.request(
            "POST",
            f"/api/mailboxes/{mailbox_id}/messages/msg_spam_1/report-spam",
        )
        self.assertEqual(status_code, 502)
        self.assertIn("temporarily unavailable", body["detail"])

    # =========================================================================
    # 2. DELETE (TRASH) TESTS
    # =========================================================================

    @patch("backend.app.services.gmail.client.TokenStore.get_credentials")
    @patch("backend.app.services.gmail.client.build_gmail_service")
    def test_delete_message_success(self, mock_build_svc: MagicMock, mock_get_creds: MagicMock) -> None:
        mailbox_id = self._seed_mailbox()
        mock_creds = MagicMock()
        mock_creds.scopes = ["https://www.googleapis.com/auth/gmail.modify"]
        mock_get_creds.return_value = mock_creds

        mock_svc = MagicMock()
        mock_messages = mock_svc.users.return_value.messages.return_value
        mock_messages.trash.return_value.execute.return_value = {
            "id": "msg_delete_1",
            "labelIds": ["TRASH"],
        }
        mock_build_svc.return_value = mock_svc

        status_code, body = self.request(
            "POST",
            f"/api/mailboxes/{mailbox_id}/messages/msg_delete_1/delete",
        )

        self.assertEqual(status_code, 200)
        self.assertTrue(body["success"])
        self.assertEqual(body["action"], "DELETE")
        self.assertEqual(body["message_id"], "msg_delete_1")
        self.assertEqual(body["status"], "TRASHED")

        # Verify trash API was called
        mock_messages.trash.assert_called_once_with(
            userId="me",
            id="msg_delete_1",
        )

    def test_delete_message_invalid_mailbox_404(self) -> None:
        status_code, body = self.request(
            "POST",
            "/api/mailboxes/99999/messages/msg_delete_1/delete",
        )
        self.assertEqual(status_code, 404)
        self.assertIn("Mailbox not found", body["detail"])

    @patch("backend.app.services.gmail.client.TokenStore.get_credentials")
    @patch("backend.app.services.gmail.client.build_gmail_service")
    def test_delete_message_missing_message_404(self, mock_build_svc: MagicMock, mock_get_creds: MagicMock) -> None:
        mailbox_id = self._seed_mailbox()
        mock_creds = MagicMock()
        mock_creds.scopes = ["https://www.googleapis.com/auth/gmail.modify"]
        mock_get_creds.return_value = mock_creds

        mock_svc = MagicMock()
        mock_svc.users().messages().trash().execute.side_effect = _make_http_error(404, "Not Found")
        mock_build_svc.return_value = mock_svc

        status_code, body = self.request(
            "POST",
            f"/api/mailboxes/{mailbox_id}/messages/missing_msg/delete",
        )
        self.assertEqual(status_code, 404)
        self.assertIn("not found", body["detail"])

    @patch("backend.app.services.gmail.client.TokenStore.get_credentials")
    def test_delete_message_insufficient_scope_403(self, mock_get_creds: MagicMock) -> None:
        mailbox_id = self._seed_mailbox()
        mock_creds = MagicMock()
        mock_creds.scopes = ["https://www.googleapis.com/auth/gmail.readonly"]
        mock_get_creds.return_value = mock_creds

        status_code, body = self.request(
            "POST",
            f"/api/mailboxes/{mailbox_id}/messages/msg_delete_1/delete",
        )
        self.assertEqual(status_code, 403)
        self.assertIn("Additional Gmail permission required", body["detail"])
        self.assertEqual(body["error"]["code"], "INSUFFICIENT_PERMISSIONS")

    @patch("backend.app.services.gmail.client.TokenStore.get_credentials")
    @patch("backend.app.services.gmail.client.build_gmail_service")
    def test_delete_message_provider_500_raises_502(self, mock_build_svc: MagicMock, mock_get_creds: MagicMock) -> None:
        mailbox_id = self._seed_mailbox()
        mock_creds = MagicMock()
        mock_creds.scopes = ["https://www.googleapis.com/auth/gmail.modify"]
        mock_get_creds.return_value = mock_creds

        mock_svc = MagicMock()
        mock_svc.users().messages().trash().execute.side_effect = _make_http_error(503, "Unavailable")
        mock_build_svc.return_value = mock_svc

        status_code, body = self.request(
            "POST",
            f"/api/mailboxes/{mailbox_id}/messages/msg_delete_1/delete",
        )
        self.assertEqual(status_code, 502)
        self.assertIn("temporarily unavailable", body["detail"])

    # =========================================================================
    # 3. BLOCK SENDER (FILTER) TESTS
    # =========================================================================

    @patch("backend.app.services.gmail.client.TokenStore.get_credentials")
    @patch("backend.app.services.gmail.client.build_gmail_service")
    def test_block_sender_success_creates_filter(self, mock_build_svc: MagicMock, mock_get_creds: MagicMock) -> None:
        mailbox_id = self._seed_mailbox()
        mock_creds = MagicMock()
        mock_creds.scopes = ["https://www.googleapis.com/auth/gmail.settings.basic"]
        mock_get_creds.return_value = mock_creds

        mock_svc = MagicMock()
        mock_messages = mock_svc.users.return_value.messages.return_value
        mock_filters = mock_svc.users.return_value.settings.return_value.filters.return_value

        # Mock message metadata fetching From header
        mock_messages.get.return_value.execute.return_value = {
            "id": "msg_block_1",
            "payload": {
                "headers": [
                    {"name": "From", "value": "Scammer John <badguy@attacker.com>"},
                    {"name": "Subject", "value": "Urgent wire required"},
                ]
            },
        }
        # Mock list filters returning no matching filter
        mock_filters.list.return_value.execute.return_value = {
            "filter": [
                {"id": "filt_other", "criteria": {"from": "friend@company.com"}}
            ]
        }
        # Mock create filter
        mock_filters.create.return_value.execute.return_value = {
            "id": "created_filter_999",
            "criteria": {"from": "badguy@attacker.com"},
            "action": {"removeLabelIds": ["INBOX"], "addLabelIds": ["TRASH"]},
        }
        mock_build_svc.return_value = mock_svc

        status_code, body = self.request(
            "POST",
            f"/api/mailboxes/{mailbox_id}/messages/msg_block_1/block-sender",
        )

        self.assertEqual(status_code, 200)
        self.assertTrue(body["success"])
        self.assertEqual(body["action"], "BLOCK_SENDER")
        self.assertEqual(body["sender"], "badguy@attacker.com")
        self.assertEqual(body["filter_id"], "created_filter_999")
        self.assertFalse(body["already_blocked"])

        # Verify filter creation criteria
        mock_filters.create.assert_called_once_with(
            userId="me",
            body={
                "criteria": {"from": "badguy@attacker.com"},
                "action": {"removeLabelIds": ["INBOX"], "addLabelIds": ["TRASH"]},
            },
        )

    @patch("backend.app.services.gmail.client.TokenStore.get_credentials")
    @patch("backend.app.services.gmail.client.build_gmail_service")
    def test_block_sender_idempotency_already_blocked(self, mock_build_svc: MagicMock, mock_get_creds: MagicMock) -> None:
        """When a filter for this sender already exists, return already_blocked=True without duplicate creation."""
        mailbox_id = self._seed_mailbox()
        mock_creds = MagicMock()
        mock_creds.scopes = ["https://www.googleapis.com/auth/gmail.settings.basic"]
        mock_get_creds.return_value = mock_creds

        mock_svc = MagicMock()
        mock_messages = mock_svc.users.return_value.messages.return_value
        mock_filters = mock_svc.users.return_value.settings.return_value.filters.return_value

        mock_messages.get.return_value.execute.return_value = {
            "id": "msg_block_dup",
            "payload": {
                "headers": [
                    {"name": "From", "value": "attacker@phish.net"},
                ]
            },
        }
        # Existing filter matches attacker@phish.net
        mock_filters.list.return_value.execute.return_value = {
            "filter": [
                {"id": "existing_filter_42", "criteria": {"from": "attacker@phish.net"}}
            ]
        }
        mock_build_svc.return_value = mock_svc

        status_code, body = self.request(
            "POST",
            f"/api/mailboxes/{mailbox_id}/messages/msg_block_dup/block-sender",
        )

        self.assertEqual(status_code, 200)
        self.assertTrue(body["success"])
        self.assertEqual(body["sender"], "attacker@phish.net")
        self.assertEqual(body["filter_id"], "existing_filter_42")
        self.assertTrue(body["already_blocked"])

        # Ensure create filter was NOT called
        mock_filters.create.assert_not_called()

    @patch("backend.app.services.gmail.client.TokenStore.get_credentials")
    @patch("backend.app.services.gmail.client.build_gmail_service")
    def test_block_sender_missing_from_header_returns_400(self, mock_build_svc: MagicMock, mock_get_creds: MagicMock) -> None:
        mailbox_id = self._seed_mailbox()
        mock_creds = MagicMock()
        mock_creds.scopes = ["https://www.googleapis.com/auth/gmail.settings.basic"]
        mock_get_creds.return_value = mock_creds

        mock_svc = MagicMock()
        mock_svc.users().messages().get().execute.return_value = {
            "id": "msg_no_from",
            "payload": {"headers": []},
        }
        mock_build_svc.return_value = mock_svc

        status_code, body = self.request(
            "POST",
            f"/api/mailboxes/{mailbox_id}/messages/msg_no_from/block-sender",
        )
        self.assertEqual(status_code, 400)
        self.assertIn("Unable to extract a valid sender", body["detail"])

    @patch("backend.app.services.gmail.client.TokenStore.get_credentials")
    def test_block_sender_insufficient_scope_403(self, mock_get_creds: MagicMock) -> None:
        mailbox_id = self._seed_mailbox()
        mock_creds = MagicMock()
        mock_creds.scopes = ["https://www.googleapis.com/auth/gmail.readonly"]
        mock_get_creds.return_value = mock_creds

        status_code, body = self.request(
            "POST",
            f"/api/mailboxes/{mailbox_id}/messages/msg_block_1/block-sender",
        )
        self.assertEqual(status_code, 403)
        self.assertIn("Additional Gmail permission required", body["detail"])
        self.assertEqual(body["error"]["code"], "INSUFFICIENT_PERMISSIONS")

    @patch("backend.app.services.gmail.client.TokenStore.get_credentials")
    @patch("backend.app.services.gmail.client.build_gmail_service")
    def test_block_sender_provider_500_raises_502(self, mock_build_svc: MagicMock, mock_get_creds: MagicMock) -> None:
        mailbox_id = self._seed_mailbox()
        mock_creds = MagicMock()
        mock_creds.scopes = ["https://www.googleapis.com/auth/gmail.settings.basic"]
        mock_get_creds.return_value = mock_creds

        mock_svc = MagicMock()
        mock_svc.users().messages().get().execute.side_effect = _make_http_error(500, "Server Error")
        mock_build_svc.return_value = mock_svc

        status_code, body = self.request(
            "POST",
            f"/api/mailboxes/{mailbox_id}/messages/msg_block_1/block-sender",
        )
        self.assertEqual(status_code, 502)
        self.assertIn("temporarily unavailable", body["detail"])

    # =========================================================================
    # 4. TOKEN SAFETY AUDIT TEST
    # =========================================================================

    @patch("backend.app.services.gmail.client.TokenStore.get_credentials")
    @patch("backend.app.services.gmail.client.build_gmail_service")
    def test_zero_credential_exposure_in_responses(self, mock_build_svc: MagicMock, mock_get_creds: MagicMock) -> None:
        """Ensure no auth tokens, access tokens, or refresh tokens are ever leaked in API responses."""
        mailbox_id = self._seed_mailbox()
        mock_creds = MagicMock()
        mock_creds.token = "secret_access_token_12345"
        mock_creds.refresh_token = "secret_refresh_token_67890"
        mock_creds.scopes = [
            "https://www.googleapis.com/auth/gmail.modify",
            "https://www.googleapis.com/auth/gmail.settings.basic",
        ]
        mock_get_creds.return_value = mock_creds

        mock_svc = MagicMock()
        mock_svc.users().messages().modify().execute.return_value = {"id": "msg_safe_1"}
        mock_svc.users().messages().trash().execute.return_value = {"id": "msg_safe_2"}
        mock_build_svc.return_value = mock_svc

        for endpoint in ["report-spam", "delete"]:
            _, body = self.request("POST", f"/api/mailboxes/{mailbox_id}/messages/msg_safe_1/{endpoint}")
            body_str = json.dumps(body)
            self.assertNotIn("secret_access_token", body_str)
            self.assertNotIn("secret_refresh_token", body_str)


if __name__ == "__main__":
    unittest.main()
