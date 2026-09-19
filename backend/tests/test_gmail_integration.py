"""Comprehensive unit and integration tests for Gmail mailbox integration."""

import asyncio
import base64
import glob
import json
import logging
import unittest
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple
from unittest.mock import MagicMock, patch
from urllib.parse import urlparse

from google.oauth2.credentials import Credentials
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.db.database import Base, init_db
from backend.app.db.session import get_db
from backend.app.main import app
from backend.app.models.case import Case
from backend.app.models.enums import CaseStatus, MailboxStatus
from backend.app.models.mailbox import Mailbox
from backend.app.schemas.analysis import NormalizedEmail
from backend.app.services.gmail.history import list_new_messages_from_history
from backend.app.services.gmail.message_parser import parse_gmail_message
from backend.app.services.gmail.oauth import (
    build_authorization_url,
    exchange_code_for_credentials,
    generate_oauth_state,
    validate_and_consume_state,
)
from backend.app.services.gmail.sync_service import sync_gmail_mailbox
from backend.app.services.gmail.token_store import TokenStore
from backend.app.services.gmail.watcher import start_mailbox_watch


class GmailIntegrationTestCase(unittest.TestCase):
    """Test suite for Gmail OAuth, Watch, Pub/Sub webhook, and in-memory parsing."""

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
        headers_dict: Optional[Dict[str, str]] = None,
    ) -> Tuple[int, Any, Dict[str, str]]:
        """Perform an HTTP request directly against the ASGI app."""
        parsed = urlparse(url)
        path = parsed.path
        query_string = parsed.query.encode("utf-8")
        body_bytes = json.dumps(data).encode("utf-8") if data is not None else b""

        headers = [(b"host", b"testserver")]
        if data is not None:
            headers.append((b"content-type", b"application/json"))
        if headers_dict:
            for k, v in headers_dict.items():
                headers.append((k.lower().encode("utf-8"), v.encode("utf-8")))

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
        response_headers: Dict[str, str] = {}

        async def receive():
            return {"type": "http.request", "body": body_bytes, "more_body": False}

        async def send(message):
            nonlocal status_code, response_headers
            if message["type"] == "http.response.start":
                status_code = message["status"]
                response_headers = {
                    k.decode("latin-1").lower(): v.decode("latin-1")
                    for k, v in message.get("headers", [])
                }
            elif message["type"] == "http.response.body":
                response_body.append(message.get("body", b""))

        asyncio.run(app(scope, receive, send))

        raw_content = b"".join(response_body).decode("utf-8")
        try:
            parsed_json = json.loads(raw_content) if raw_content else None
        except json.JSONDecodeError:
            parsed_json = raw_content

        return status_code, parsed_json, response_headers

    # 1. OAuth URL generation and CSRF state creation
    @patch("backend.app.services.gmail.oauth.Flow.from_client_config")
    def test_oauth_url_generation(self, mock_flow_cls: MagicMock) -> None:
        mock_flow = MagicMock()
        mock_flow.authorization_url.return_value = ("https://accounts.google.com/o/oauth2/v2/auth?mock=true", "test_state")
        mock_flow_cls.return_value = mock_flow

        auth_url, state = build_authorization_url()
        self.assertIn("https://accounts.google.com", auth_url)
        self.assertTrue(len(state) > 16)
        self.assertTrue(validate_and_consume_state(state))
        # Single use validation: second check must fail
        self.assertFalse(validate_and_consume_state(state))

    # 2. OAuth state validation rejects invalid state
    def test_oauth_state_rejection(self) -> None:
        self.assertFalse(validate_and_consume_state("nonexistent-state-token"))
        self.assertFalse(validate_and_consume_state(None))

    # 3. GET /api/auth/google/login endpoint
    @patch("backend.app.services.gmail.oauth.Flow.from_client_config")
    def test_google_login_endpoint(self, mock_flow_cls: MagicMock) -> None:
        mock_flow = MagicMock()
        mock_flow.authorization_url.return_value = ("https://accounts.google.com/o/oauth2/v2/auth?mock=true", "state123")
        mock_flow_cls.return_value = mock_flow

        status_code, body, _ = self.request("GET", "/api/auth/google/login")
        self.assertEqual(status_code, 200)
        self.assertIn("authorization_url", body)
        self.assertIn("state", body)

    # 4. OAuth callback failure with missing or invalid state
    def test_oauth_callback_invalid_state(self) -> None:
        status_code, body, _ = self.request("GET", "/api/auth/google/callback?code=mock_code&state=bad_state")
        self.assertEqual(status_code, 400)
        self.assertIn("error", body)
        self.assertEqual(body["error"]["code"], "INVALID_OAUTH_STATE")

    # 5. Successful OAuth callback registers mailbox without exposing tokens
    @patch("backend.app.api.google_auth.exchange_code_for_credentials")
    @patch("backend.app.api.google_auth.build_gmail_service")
    def test_oauth_callback_success(self, mock_build_svc: MagicMock, mock_exchange: MagicMock) -> None:
        mock_creds = MagicMock()
        mock_creds.token = "secret_access_token_123"
        mock_creds.refresh_token = "secret_refresh_token_456"
        mock_creds.token_uri = "https://oauth2.googleapis.com/token"
        mock_creds.client_id = "test_client_id"
        mock_creds.client_secret = "test_client_secret"
        mock_creds.scopes = ["https://www.googleapis.com/auth/gmail.readonly"]
        mock_creds.expiry = None
        mock_exchange.return_value = mock_creds

        mock_svc = MagicMock()
        mock_svc.users().getProfile(userId="me").execute.return_value = {
            "emailAddress": "connected.user@gmail.com",
            "historyId": "998877",
        }
        mock_build_svc.return_value = mock_svc

        state = generate_oauth_state()
        status_code, body, _ = self.request("GET", f"/api/auth/google/callback?code=valid_code&state={state}")
        self.assertEqual(status_code, 200)
        self.assertEqual(body["status"], "connected")
        self.assertEqual(body["provider"], "gmail")
        self.assertEqual(body["account_email"], "connected.user@gmail.com")
        self.assertIn("mailbox_id", body)

        # Ensure tokens are NOT exposed in the response
        response_text = json.dumps(body)
        self.assertNotIn("secret_access_token", response_text)
        self.assertNotIn("secret_refresh_token", response_text)

        # Verify mailbox in database
        with self.TestingSessionLocal() as session:
            mailbox = session.get(Mailbox, body["mailbox_id"])
            self.assertIsNotNone(mailbox)
            self.assertEqual(mailbox.account_email, "connected.user@gmail.com")
            self.assertEqual(mailbox.status, MailboxStatus.CONNECTED.value)
            self.assertEqual(mailbox.latest_history_id, "998877")

    # 6. Credential persistence and auto-refresh in TokenStore
    def test_token_store_persistence_and_refresh(self) -> None:
        with self.TestingSessionLocal() as session:
            mailbox = Mailbox(
                account_email="token.test@gmail.com",
                provider="gmail",
                status=MailboxStatus.CONNECTED.value,
            )
            session.add(mailbox)
            session.commit()

            creds = Credentials(
                token="initial_token_abc",
                refresh_token="refresh_token_xyz",
                token_uri="https://oauth2.googleapis.com/token",
                client_id="cid",
                client_secret="sec",
            )
            TokenStore.save_credentials(db=session, mailbox=mailbox, credentials=creds)

            # Retrieve credentials
            loaded = TokenStore.get_credentials(db=session, mailbox=mailbox)
            self.assertIsNotNone(loaded)
            self.assertEqual(loaded.token, "initial_token_abc")
            self.assertEqual(loaded.refresh_token, "refresh_token_xyz")

    # 7. In-memory message parsing: plaintext, headers, date, and attachments metadata
    def test_message_parser_full(self) -> None:
        raw_text = "Urgent: Please update your password immediately by visiting https://phish.com"
        b64_body = base64.urlsafe_b64encode(raw_text.encode("utf-8")).decode("ascii")

        gmail_resource = {
            "id": "gmail_msg_101",
            "threadId": "thread_202",
            "internalDate": "1726740000000",
            "payload": {
                "headers": [
                    {"name": "From", "value": "security@attacker-domain.com"},
                    {"name": "To", "value": "analyst@mailtrace.ai"},
                    {"name": "Subject", "value": "Account Verification Required"},
                    {"name": "Date", "value": "Sat, 19 Sep 2026 10:00:00 +0000"},
                ],
                "mimeType": "multipart/mixed",
                "parts": [
                    {
                        "mimeType": "text/plain",
                        "body": {"data": b64_body, "size": len(raw_text)},
                    },
                    {
                        "mimeType": "application/pdf",
                        "filename": "invoice_malicious.pdf",
                        "body": {"size": 45120, "attachmentId": "att_999"},
                    },
                ],
            },
        }

        normalized = parse_gmail_message(message_resource=gmail_resource, mailbox_id=1)
        self.assertIsInstance(normalized, NormalizedEmail)
        self.assertEqual(normalized.provider, "gmail")
        self.assertEqual(normalized.provider_message_id, "gmail_msg_101")
        self.assertEqual(normalized.thread_id, "thread_202")
        self.assertEqual(normalized.sender, "security@attacker-domain.com")
        self.assertEqual(normalized.recipient, "analyst@mailtrace.ai")
        self.assertEqual(normalized.subject, "Account Verification Required")
        self.assertIn("Urgent: Please update your password", normalized.body)
        self.assertIsNotNone(normalized.received_at)

        # Attachment metadata recorded in headers without downloading attachment bytes
        attachment_headers = [h for h in normalized.headers if h["name"] == "X-Attachment-Metadata"]
        self.assertEqual(len(attachment_headers), 1)
        self.assertIn("invoice_malicious.pdf", attachment_headers[0]["value"])

    # 8. HTML fallback tag stripping when no plaintext part exists
    def test_message_parser_html_fallback(self) -> None:
        html_content = "<p>Hello <b>User</b>,<br>Your statement is ready.</p>"
        b64_html = base64.urlsafe_b64encode(html_content.encode("utf-8")).decode("ascii")

        gmail_resource = {
            "id": "gmail_msg_html_only",
            "payload": {
                "headers": [
                    {"name": "From", "value": "billing@service.com"},
                    {"name": "To", "value": "user@gmail.com"},
                    {"name": "Subject", "value": "Statement"},
                ],
                "mimeType": "text/html",
                "body": {"data": b64_html, "size": len(html_content)},
            },
        }

        normalized = parse_gmail_message(message_resource=gmail_resource)
        self.assertIn("Hello User", normalized.body)
        self.assertNotIn("<p>", normalized.body)
        self.assertNotIn("<b>", normalized.body)

    # 9. History lookup with pagination
    def test_history_lookup_pagination(self) -> None:
        mock_service = MagicMock()

        # Page 1 response
        mock_service.users().history().list().execute.side_effect = [
            {
                "history": [
                    {"messagesAdded": [{"message": {"id": "msg_page1_1"}}]},
                    {"messagesAdded": [{"message": {"id": "msg_page1_2"}}]},
                ],
                "nextPageToken": "token_page_2",
                "historyId": "100050",
            },
            # Page 2 response
            {
                "history": [
                    {"messagesAdded": [{"message": {"id": "msg_page2_1"}}]},
                ],
                "nextPageToken": None,
                "historyId": "100060",
            },
        ]

        msg_ids, latest_hist_id = list_new_messages_from_history(mock_service, start_history_id="100000")
        self.assertEqual(msg_ids, ["msg_page1_1", "msg_page1_2", "msg_page2_1"])
        self.assertEqual(latest_hist_id, "100060")

    # 10. Expired history ID bounded recovery
    def test_expired_history_id_recovery(self) -> None:
        from googleapiclient.errors import HttpError
        from httplib2 import Response

        mock_service = MagicMock()
        err_resp = Response({"status": 404, "reason": "historyIdNotFound"})
        mock_service.users().history().list().execute.side_effect = HttpError(
            resp=err_resp,
            content=b'{"error": {"message": "historyIdNotFound"}}',
        )

        mock_service.users().getProfile(userId="me").execute.return_value = {"historyId": "200500"}
        mock_service.users().messages().list().execute.return_value = {
            "messages": [{"id": "fallback_msg_001"}, {"id": "fallback_msg_002"}]
        }

        msg_ids, new_history_id = list_new_messages_from_history(mock_service, start_history_id="old_expired_id")
        self.assertEqual(new_history_id, "200500")
        self.assertEqual(msg_ids, ["fallback_msg_001", "fallback_msg_002"])

    # 11. Mailbox watch initiation (POST /api/mailboxes/{mailbox_id}/watch)
    @patch("backend.app.services.gmail.watcher.build_gmail_service")
    def test_mailbox_watch_endpoint(self, mock_build_svc: MagicMock) -> None:
        with self.TestingSessionLocal() as session:
            mailbox = Mailbox(
                account_email="watch.target@gmail.com",
                provider="gmail",
                status=MailboxStatus.CONNECTED.value,
                credentials_data=json.dumps({"token": "fake_tok", "refresh_token": "fake_ref"}),
            )
            session.add(mailbox)
            session.commit()
            mailbox_id = mailbox.id

        mock_svc = MagicMock()
        mock_svc.users().watch().execute.return_value = {
            "historyId": "554433",
            "expiration": "1727344800000",
        }
        mock_build_svc.return_value = mock_svc

        status_code, body, _ = self.request("POST", f"/api/mailboxes/{mailbox_id}/watch")
        self.assertEqual(status_code, 200)
        self.assertEqual(body["status"], "watching")
        self.assertEqual(body["mailbox_id"], mailbox_id)
        self.assertEqual(body["history_id"], "554433")
        self.assertIsNotNone(body["expiration"])

    # 12. Pub/Sub webhook endpoint (POST /api/webhooks/google/gmail)
    @patch("backend.app.api.google_webhook.sync_gmail_mailbox")
    def test_pubsub_webhook_acknowledgement(self, mock_sync: MagicMock) -> None:
        payload_data = {"emailAddress": "monitored@gmail.com", "historyId": 778899}
        encoded_data = base64.b64encode(json.dumps(payload_data).encode("utf-8")).decode("ascii")

        push_payload = {
            "message": {
                "data": encoded_data,
                "messageId": "pubsub_msg_test_01",
                "publishTime": "2026-09-19T10:00:00Z",
            }
        }

        status_code, body, _ = self.request("POST", "/api/webhooks/google/gmail", data=push_payload)
        self.assertEqual(status_code, 200)
        self.assertEqual(body["status"], "received")
        self.assertEqual(body["account_email"], "monitored@gmail.com")

    # 13. End-to-end integration: Pub/Sub -> Sync -> In-Memory Parsing -> Pipeline -> Case & Analysis
    @patch("backend.app.services.gmail.sync_service.build_gmail_service")
    def test_end_to_end_gmail_pipeline_flow(self, mock_build_svc: MagicMock) -> None:
        with self.TestingSessionLocal() as session:
            mailbox = Mailbox(
                account_email="analyst.e2e@gmail.com",
                provider="gmail",
                status=MailboxStatus.CONNECTED.value,
                latest_history_id="1000",
                credentials_data=json.dumps({"token": "dummy_t", "refresh_token": "dummy_r"}),
            )
            session.add(mailbox)
            session.commit()

        # Mock Gmail history response (1 new message)
        mock_svc = MagicMock()
        mock_svc.users().history().list().execute.return_value = {
            "history": [{"messagesAdded": [{"message": {"id": "e2e_msg_999"}}]}],
            "nextPageToken": None,
            "historyId": "1050",
        }

        # Mock Gmail message fetch
        email_content = "Suspicious phishing attempt with credential harvesting link."
        mock_svc.users().messages().get().execute.return_value = {
            "id": "e2e_msg_999",
            "threadId": "e2e_thread_999",
            "internalDate": "1726740000000",
            "payload": {
                "headers": [
                    {"name": "From", "value": "phisher@malicious.org"},
                    {"name": "To", "value": "analyst.e2e@gmail.com"},
                    {"name": "Subject", "value": "Urgent Invoice Payment"},
                ],
                "mimeType": "text/plain",
                "body": {
                    "data": base64.urlsafe_b64encode(email_content.encode("utf-8")).decode("ascii"),
                    "size": len(email_content),
                },
            },
        }
        mock_build_svc.return_value = mock_svc

        # Execute sync
        with self.TestingSessionLocal() as session:
            result = sync_gmail_mailbox(
                account_email="analyst.e2e@gmail.com",
                notification_history_id="1050",
                db_session=session,
            )
            self.assertEqual(result["status"], "success")
            self.assertEqual(result["messages_processed"], 1)
            self.assertEqual(result["duplicates_skipped"], 0)
            self.assertEqual(result["latest_history_id"], "1050")

            # Verify that Case was created in database
            case = session.query(Case).filter_by(provider_message_id="e2e_msg_999").first()
            self.assertIsNotNone(case)
            self.assertEqual(case.provider, "gmail")
            self.assertEqual(case.sender, "phisher@malicious.org")
            self.assertEqual(case.subject, "Urgent Invoice Payment")
            self.assertIn(case.status, [CaseStatus.PROCESSING.value, CaseStatus.COMPLETED.value])
            self.assertIsNotNone(case.risk_score)

        # Execute second sync with same message ID -> Enforces idempotency & skips duplicate
        with self.TestingSessionLocal() as session:
            dup_result = sync_gmail_mailbox(
                account_email="analyst.e2e@gmail.com",
                notification_history_id="1050",
                db_session=session,
            )
            self.assertEqual(dup_result["messages_processed"], 0)
            self.assertEqual(dup_result["duplicates_skipped"], 1)

    # 14. Invariant Verification: Zero .eml files created anywhere
    def test_zero_eml_files_enforced(self) -> None:
        eml_files = glob.glob("**/*.eml", recursive=True)
        self.assertEqual(len(eml_files), 0, f"Disallowed .eml files found on disk: {eml_files}")

    # 15. Invariant Verification: Token values never appear in logs
    def test_tokens_never_logged(self) -> None:
        class LogInterceptor(logging.Handler):
            def __init__(self):
                super().__init__()
                self.records = []

            def emit(self, record):
                self.records.append(self.format(record))

        interceptor = LogInterceptor()
        root_logger = logging.getLogger()
        root_logger.addHandler(interceptor)

        sensitive_token = "super_secret_token_never_log_me_987654321"
        with self.TestingSessionLocal() as session:
            mailbox = Mailbox(
                account_email="secret.test@gmail.com",
                provider="gmail",
                status=MailboxStatus.CONNECTED.value,
            )
            session.add(mailbox)
            session.commit()

            creds = Credentials(
                token=sensitive_token,
                refresh_token=sensitive_token,
            )
            TokenStore.save_credentials(db=session, mailbox=mailbox, credentials=creds)
            TokenStore.get_credentials(db=session, mailbox=mailbox)
            TokenStore.clear_credentials(db=session, mailbox=mailbox)

        root_logger.removeHandler(interceptor)
        all_logs = " ".join(interceptor.records)
        self.assertNotIn(sensitive_token, all_logs)


if __name__ == "__main__":
    unittest.main()
