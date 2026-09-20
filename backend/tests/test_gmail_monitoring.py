"""Comprehensive unit and integration tests for Gmail monitoring, alerting, and SOC escalation."""

import base64
import glob
import json
import logging
import unittest
from datetime import datetime, timedelta, timezone
from typing import Any, Dict
from unittest.mock import MagicMock, patch

from google.oauth2.credentials import Credentials
from googleapiclient.errors import HttpError
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.core.config import settings
from backend.app.db.database import Base
from backend.app.db.session import get_db
from backend.app.main import app
from backend.app.models.alert import SecurityAlert
from backend.app.models.case import Case
from backend.app.models.enums import AlertStatus, CaseStatus, MailboxStatus
from backend.app.models.mailbox import Mailbox
from backend.app.services.gmail.history import list_new_messages_from_history
from backend.app.services.gmail.sync_service import sync_gmail_mailbox
from backend.app.services.gmail.token_store import TokenStore
from backend.app.services.gmail.watcher import (
    renew_mailbox_watch_if_needed,
    start_mailbox_watch,
    stop_mailbox_watch,
)


class GmailMonitoringTestCase(unittest.IsolatedAsyncioTestCase):
    """Test suite verifying Chunk 4 automatic monitoring, alerting, and SOC escalation."""

    @classmethod
    def setUpClass(cls) -> None:
        cls._orig_client_id = settings.google_client_id
        cls._orig_client_secret = settings.google_client_secret
        cls._orig_redirect_uri = settings.google_redirect_uri
        cls._orig_pubsub_topic = settings.google_pubsub_topic

        settings.google_client_id = "test-client-id.apps.googleusercontent.com"
        settings.google_client_secret = "test-client-secret"
        settings.google_redirect_uri = "http://127.0.0.1:8000/api/auth/google/callback"
        settings.google_pubsub_topic = "projects/test-project/topics/gmail-monitoring"

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
        settings.google_client_id = cls._orig_client_id
        settings.google_client_secret = cls._orig_client_secret
        settings.google_redirect_uri = cls._orig_redirect_uri
        settings.google_pubsub_topic = cls._orig_pubsub_topic
        app.dependency_overrides.clear()

    def setUp(self) -> None:
        Base.metadata.drop_all(bind=self.test_engine)
        Base.metadata.create_all(bind=self.test_engine)

        with self.TestingSessionLocal() as session:
            mailbox = Mailbox(
                account_email="analyst.soc@gmail.com",
                provider="gmail",
                status=MailboxStatus.CONNECTED.value,
                latest_history_id="5000",
            )
            session.add(mailbox)
            session.commit()
            session.refresh(mailbox)
            self.mailbox_id = mailbox.id

            mock_creds = Credentials(
                token="mock_access_token_monitoring",
                refresh_token="mock_refresh_token_monitoring",
                token_uri="https://oauth2.googleapis.com/token",
                client_id=settings.google_client_id,
                client_secret=settings.google_client_secret,
                scopes=["https://www.googleapis.com/auth/gmail.readonly"],
            )
            TokenStore.save_credentials(db=session, mailbox=mailbox, credentials=mock_creds)

    def tearDown(self) -> None:
        Base.metadata.drop_all(bind=self.test_engine)

    # -------------------------------------------------------------------------
    # 1. Watch Lifecycle: Registration, Renewal, Expiration, Duplicate Avoidance
    # -------------------------------------------------------------------------
    @patch("backend.app.services.gmail.watcher.build_gmail_service")
    def test_watch_creation_and_lifecycle_logging(self, mock_build_svc: MagicMock) -> None:
        mock_svc = MagicMock()
        mock_svc.users().watch().execute.return_value = {
            "historyId": "5050",
            "expiration": "1727000000000",
        }
        mock_build_svc.return_value = mock_svc

        with self.assertLogs("mailtrace", level="INFO") as log_ctx:
            with self.TestingSessionLocal() as session:
                mailbox = session.get(Mailbox, self.mailbox_id)
                res = start_mailbox_watch(db=session, mailbox=mailbox)

                self.assertEqual(res["status"], "watching")
                self.assertEqual(res["history_id"], "5050")
                self.assertIsNotNone(res["expiration"])

                # Verify DB persistence
                session.refresh(mailbox)
                self.assertEqual(mailbox.latest_history_id, "5050")
                self.assertIsNotNone(mailbox.watch_expiration)

            # Check structured log tag
            logged_text = " ".join(log_ctx.output)
            self.assertIn("WATCH_CREATED", logged_text)

    @patch("backend.app.services.gmail.watcher.build_gmail_service")
    def test_duplicate_watch_prevention_when_active(self, mock_build_svc: MagicMock) -> None:
        future_exp = datetime.now(timezone.utc) + timedelta(days=5)
        with self.TestingSessionLocal() as session:
            mailbox = session.get(Mailbox, self.mailbox_id)
            mailbox.watch_expiration = future_exp
            session.commit()

            # Attempt renewal when watch is healthy and far from expiry
            res = renew_mailbox_watch_if_needed(db=session, mailbox=mailbox, buffer_minutes=60, force=False)
            self.assertEqual(res["status"], "watching")
            self.assertFalse(res.get("renewed", True))
            # Must NOT call Gmail API again
            mock_build_svc.assert_not_called()

    @patch("backend.app.services.gmail.watcher.build_gmail_service")
    def test_watch_renewal_when_nearing_expiration(self, mock_build_svc: MagicMock) -> None:
        mock_svc = MagicMock()
        mock_svc.users().watch().execute.return_value = {
            "historyId": "5100",
            "expiration": "1727500000000",
        }
        mock_build_svc.return_value = mock_svc

        # Watch expiring in 15 minutes (within buffer of 60 minutes)
        soon_exp = datetime.now(timezone.utc) + timedelta(minutes=15)
        with self.assertLogs("mailtrace", level="INFO") as log_ctx:
            with self.TestingSessionLocal() as session:
                mailbox = session.get(Mailbox, self.mailbox_id)
                mailbox.watch_expiration = soon_exp
                session.commit()

                res = renew_mailbox_watch_if_needed(db=session, mailbox=mailbox, buffer_minutes=60)
                self.assertEqual(res["status"], "watching")
                self.assertTrue(res.get("renewed", False))
                self.assertEqual(res["history_id"], "5100")

            logged_text = " ".join(log_ctx.output)
            self.assertIn("WATCH_RENEWED", logged_text)

    @patch("backend.app.services.gmail.watcher.build_gmail_service")
    def test_watch_restart_when_expired(self, mock_build_svc: MagicMock) -> None:
        mock_svc = MagicMock()
        mock_svc.users().watch().execute.return_value = {
            "historyId": "5200",
            "expiration": "1727800000000",
        }
        mock_build_svc.return_value = mock_svc

        # Watch already expired 1 hour ago
        past_exp = datetime.now(timezone.utc) - timedelta(hours=1)
        with self.assertLogs("mailtrace", level="INFO") as log_ctx:
            with self.TestingSessionLocal() as session:
                mailbox = session.get(Mailbox, self.mailbox_id)
                mailbox.watch_expiration = past_exp
                session.commit()

                res = renew_mailbox_watch_if_needed(db=session, mailbox=mailbox)
                self.assertEqual(res["status"], "watching")
                self.assertTrue(res.get("renewed", False))

            logged_text = " ".join(log_ctx.output)
            self.assertTrue("WATCH_EXPIRED" in logged_text or "WATCH_RESTARTED" in logged_text)

    # -------------------------------------------------------------------------
    # 2. History Synchronization & Gap Recovery (HTTP 404 Fallback)
    # -------------------------------------------------------------------------
    def test_history_new_message_discovery_and_deduplication(self) -> None:
        mock_service = MagicMock()
        mock_service.users().history().list().execute.return_value = {
            "historyId": "5050",
            "history": [
                {
                    "messagesAdded": [
                        {"message": {"id": "msg_001", "threadId": "th_001"}},
                        {"message": {"id": "msg_002", "threadId": "th_002"}},
                        {"message": {"id": "msg_001", "threadId": "th_001"}},  # Duplicate in response
                    ]
                }
            ],
        }

        msg_ids, new_history_id = list_new_messages_from_history(
            service=mock_service,
            start_history_id="5000",
        )
        self.assertEqual(len(msg_ids), 2)
        self.assertEqual(msg_ids, ["msg_001", "msg_002"])
        self.assertEqual(new_history_id, "5050")

    def test_history_expired_404_recovery(self) -> None:
        mock_service = MagicMock()
        resp_mock = MagicMock()
        resp_mock.status = 404
        resp_mock.reason = "History ID out of range or expired"
        mock_service.users().history().list().execute.side_effect = HttpError(resp=resp_mock, content=b"404 Not Found")

        # Mock fallback profile query
        mock_service.users().getProfile().execute.return_value = {"historyId": "9999"}
        mock_service.users().messages().list().execute.return_value = {
            "messages": [{"id": "fallback_001"}, {"id": "fallback_002"}]
        }

        msg_ids, new_history_id = list_new_messages_from_history(
            service=mock_service,
            start_history_id="100",
        )
        self.assertEqual(new_history_id, "9999")
        self.assertEqual(len(msg_ids), 2)
        self.assertIn("fallback_001", msg_ids)

    # -------------------------------------------------------------------------
    # 3. Fast Pre-Open Threat Scan & Alert Policy Integration
    # -------------------------------------------------------------------------
    @patch("backend.app.services.gmail.sync_service.fetch_gmail_message_resource")
    @patch("backend.app.services.gmail.sync_service.build_gmail_service")
    def test_sync_creates_threat_alert_and_case(
        self,
        mock_build_svc: MagicMock,
        mock_fetch_msg: MagicMock,
    ) -> None:
        mock_svc = MagicMock()
        mock_svc.users().watch().execute.return_value = {"historyId": "5100", "expiration": "1727500000000"}
        mock_svc.users().history().list().execute.return_value = {
            "historyId": "5100",
            "history": [
                {
                    "messagesAdded": [
                        {"message": {"id": "malicious_msg_101", "threadId": "th_101"}},
                    ]
                }
            ],
        }
        mock_build_svc.return_value = mock_svc

        phishing_body = "URGENT: Executive Wire Transfer Instructions — Process Immediately. Send $250,000 to routing 98765."
        mock_fetch_msg.return_value = {
            "id": "malicious_msg_101",
            "threadId": "th_101",
            "internalDate": "1726740000000",
            "payload": {
                "headers": [
                    {"name": "From", "value": "Chief Financial Officer <cfo@acme-corp.com>"},
                    {"name": "To", "value": "analyst.soc@gmail.com"},
                    {"name": "Reply-To", "value": "attacker-cfo@external-fraud-box.net"},
                    {"name": "Return-Path", "value": "<bounce@attacker-host.com>"},
                    {"name": "Subject", "value": "URGENT: Executive Wire Transfer Instructions — Process Immediately"},
                    {"name": "Authentication-Results", "value": "mx.google.com; spf=fail; dkim=none; dmarc=fail action=none"},
                ],
                "mimeType": "text/plain",
                "body": {
                    "data": base64.urlsafe_b64encode(phishing_body.encode("utf-8")).decode("ascii"),
                    "size": len(phishing_body),
                },
            },
        }

        with self.TestingSessionLocal() as session:
            result = sync_gmail_mailbox(
                account_email="analyst.soc@gmail.com",
                notification_history_id="5100",
                db_session=session,
            )
            self.assertEqual(result["status"], "success")
            self.assertEqual(result["messages_processed"], 1)
            self.assertEqual(result["duplicates_skipped"], 0)

            # 1. Verify SecurityAlert was created
            alert = (
                session.query(SecurityAlert)
                .filter_by(mailbox_id=self.mailbox_id, message_id="malicious_msg_101")
                .first()
            )
            self.assertIsNotNone(alert)
            self.assertIn("cfo@acme-corp.com", alert.sender)
            self.assertIn(alert.risk_level, ["HIGH", "CRITICAL", "MEDIUM"])
            self.assertEqual(alert.status, AlertStatus.UNREAD.value)
            self.assertTrue(len(alert.reasons) > 0)
            self.assertTrue(len(alert.indicators) > 0)

            # 2. Verify Case was created and linked to Alert
            case = session.query(Case).filter_by(provider_message_id="malicious_msg_101").first()
            self.assertIsNotNone(case)
            self.assertEqual(alert.case_id, case.id)
            self.assertEqual(case.risk_score, alert.risk_score)

    @patch("backend.app.services.gmail.sync_service.fetch_gmail_message_resource")
    @patch("backend.app.services.gmail.sync_service.build_gmail_service")
    def test_alert_deduplication_on_repeated_sync(
        self,
        mock_build_svc: MagicMock,
        mock_fetch_msg: MagicMock,
    ) -> None:
        mock_svc = MagicMock()
        mock_svc.users().watch().execute.return_value = {"historyId": "5200", "expiration": "1727500000000"}
        mock_svc.users().history().list().execute.return_value = {
            "historyId": "5200",
            "history": [
                {
                    "messagesAdded": [
                        {"message": {"id": "repeat_msg_202", "threadId": "th_202"}},
                    ]
                }
            ],
        }
        mock_build_svc.return_value = mock_svc

        clean_body = "Hello, here are the meeting notes from yesterday's sync."
        mock_fetch_msg.return_value = {
            "id": "repeat_msg_202",
            "threadId": "th_202",
            "internalDate": "1726740000000",
            "payload": {
                "headers": [
                    {"name": "From", "value": "Colleague <colleague@legitimate.org>"},
                    {"name": "To", "value": "analyst.soc@gmail.com"},
                    {"name": "Subject", "value": "Project Sync Notes"},
                    {"name": "Authentication-Results", "value": "mx.google.com; dkim=pass; spf=pass; dmarc=pass"},
                ],
                "mimeType": "text/plain",
                "body": {
                    "data": base64.urlsafe_b64encode(clean_body.encode("utf-8")).decode("ascii"),
                    "size": len(clean_body),
                },
            },
        }

        with self.TestingSessionLocal() as session:
            # First sync processes message
            res1 = sync_gmail_mailbox(account_email="analyst.soc@gmail.com", db_session=session)
            self.assertEqual(res1["messages_processed"], 1)

            # Second sync with same message ID skips duplicate
            res2 = sync_gmail_mailbox(account_email="analyst.soc@gmail.com", db_session=session)
            self.assertEqual(res2["messages_processed"], 0)
            self.assertEqual(res2["duplicates_skipped"], 1)

            # Verify only 1 alert exists in DB
            alerts = (
                session.query(SecurityAlert)
                .filter_by(mailbox_id=self.mailbox_id, message_id="repeat_msg_202")
                .all()
            )
            self.assertEqual(len(alerts), 1)

    # -------------------------------------------------------------------------
    # 4. Alert API: List, Read, Dismiss, On-Demand Sync
    # -------------------------------------------------------------------------
    async def test_alert_api_lifecycle(self) -> None:
        # Seed an alert
        with self.TestingSessionLocal() as session:
            alert = SecurityAlert(
                alert_id="alt_test_api_001",
                mailbox_id=self.mailbox_id,
                message_id="api_msg_001",
                sender="attacker@evil.com",
                subject="Phishing Alert",
                verdict="MALICIOUS",
                risk_score=92,
                risk_level="CRITICAL",
                confidence=0.95,
                title="CRITICAL THREAT: Phishing Alert",
                summary="High risk lure detected.",
                reasons=["Spoofed sender"],
                indicators=["AUTH_FAIL"],
                status=AlertStatus.UNREAD.value,
            )
            session.add(alert)
            session.commit()

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # 1. GET /api/mailboxes/{mailbox_id}/alerts
            list_res = await client.get(f"/api/mailboxes/{self.mailbox_id}/alerts")
            self.assertEqual(list_res.status_code, 200)
            alerts_data = list_res.json()
            self.assertEqual(len(alerts_data), 1)
            self.assertEqual(alerts_data[0]["alert_id"], "alt_test_api_001")
            self.assertEqual(alerts_data[0]["status"], "UNREAD")

            # 2. POST /api/mailboxes/{mailbox_id}/alerts/{alert_id}/read
            read_res = await client.post(f"/api/mailboxes/{self.mailbox_id}/alerts/alt_test_api_001/read")
            self.assertEqual(read_res.status_code, 200)
            self.assertEqual(read_res.json()["status"], "READ")

            # 3. POST /api/mailboxes/{mailbox_id}/alerts/{alert_id}/dismiss
            dismiss_res = await client.post(f"/api/mailboxes/{self.mailbox_id}/alerts/alt_test_api_001/dismiss")
            self.assertEqual(dismiss_res.status_code, 200)
            self.assertEqual(dismiss_res.json()["status"], "DISMISSED")

    # -------------------------------------------------------------------------
    # 5. SOC Escalation: Alert -> Deep Forensics Linkage
    # -------------------------------------------------------------------------
    @patch("backend.app.services.gmail.client.fetch_gmail_message_resource")
    @patch("backend.app.services.gmail.client.build_gmail_service")
    async def test_soc_escalation_preserves_case_alert_linkage(
        self,
        mock_build_svc: MagicMock,
        mock_fetch_msg: MagicMock,
    ) -> None:
        mock_svc = MagicMock()
        mock_build_svc.return_value = mock_svc

        email_content = "Suspicious wire transfer instructions for invoice payment."
        mock_fetch_msg.return_value = {
            "id": "soc_escalate_msg_555",
            "threadId": "th_555",
            "internalDate": "1726740000000",
            "payload": {
                "headers": [
                    {"name": "From", "value": "CFO Impersonator <ceo@spoofedcorp.com>"},
                    {"name": "To", "value": "analyst.soc@gmail.com"},
                    {"name": "Subject", "value": "Wire Transfer Needed"},
                ],
                "mimeType": "text/plain",
                "body": {
                    "data": base64.urlsafe_b64encode(email_content.encode("utf-8")).decode("ascii"),
                    "size": len(email_content),
                },
            },
        }

        # Seed pre-scan alert
        with self.TestingSessionLocal() as session:
            alert = SecurityAlert(
                alert_id="alt_escalate_555",
                mailbox_id=self.mailbox_id,
                message_id="soc_escalate_msg_555",
                sender="ceo@spoofedcorp.com",
                subject="Wire Transfer Needed",
                verdict="MALICIOUS",
                risk_score=85,
                risk_level="HIGH",
                confidence=0.90,
                title="HIGH RISK: Wire Transfer Needed",
                summary="Executive impersonation lure.",
                status=AlertStatus.UNREAD.value,
            )
            session.add(alert)
            session.commit()

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # Trigger deep analysis
            analyze_res = await client.post(
                f"/api/mailboxes/{self.mailbox_id}/messages/soc_escalate_msg_555/analyze"
            )
            self.assertEqual(analyze_res.status_code, 200)
            data = analyze_res.json()

            # Verify linkage returned
            self.assertEqual(data["alert_id"], "alt_escalate_555")
            self.assertIsNotNone(data["case"]["case_id"])
            self.assertIn("analysis", data)
            self.assertIn("forensics", data["analysis"])
            self.assertIn("authentication", data["analysis"])

        # Verify DB alert updated to INVESTIGATING with case_id
        with self.TestingSessionLocal() as session:
            alert = session.query(SecurityAlert).filter_by(alert_id="alt_escalate_555").first()
            self.assertIsNotNone(alert)
            self.assertEqual(alert.status, AlertStatus.INVESTIGATING.value)
            self.assertIsNotNone(alert.case_id)

    # -------------------------------------------------------------------------
    # 6. Pub/Sub Push Webhook Delivery
    # -------------------------------------------------------------------------
    @patch("backend.app.api.google_webhook.sync_gmail_mailbox")
    async def test_pubsub_push_notification_handling(self, mock_sync: MagicMock) -> None:
        push_payload = {
            "emailAddress": "analyst.soc@gmail.com",
            "historyId": 5555,
        }
        encoded_data = base64.b64encode(json.dumps(push_payload).encode("utf-8")).decode("utf-8")

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            res = await client.post(
                "/api/webhooks/google/gmail",
                json={
                    "message": {
                        "data": encoded_data,
                        "messageId": "pubsub_msg_999",
                        "publishTime": "2026-09-20T00:00:00Z",
                    }
                },
            )
            self.assertEqual(res.status_code, 200)
            data = res.json()
            self.assertEqual(data["status"], "received")
            self.assertEqual(data["account_email"], "analyst.soc@gmail.com")
            self.assertEqual(data["history_id"], "5555")

    # -------------------------------------------------------------------------
    # 7. Invariants: Zero .eml files written, No tokens in logs
    # -------------------------------------------------------------------------
    def test_zero_eml_files_enforced(self) -> None:
        eml_files = glob.glob("**/*.eml", recursive=True)
        self.assertEqual(len(eml_files), 0, f"Disallowed .eml files found on disk: {eml_files}")

    @patch("backend.app.services.gmail.watcher.build_gmail_service")
    def test_tokens_never_logged(self, mock_build_svc: MagicMock) -> None:
        mock_svc = MagicMock()
        mock_svc.users().watch().execute.return_value = {"historyId": "5050", "expiration": "1727000000000"}
        mock_build_svc.return_value = mock_svc

        class LogCaptor(logging.Handler):
            def __init__(self):
                super().__init__()
                self.records = []

            def emit(self, record):
                self.records.append(self.format(record))

        captor = LogCaptor()
        root_logger = logging.getLogger()
        root_logger.addHandler(captor)

        secret = "secret_token_monitoring_never_log_me"
        # Simulate normal operation
        with self.TestingSessionLocal() as session:
            mailbox = session.get(Mailbox, self.mailbox_id)
            renew_mailbox_watch_if_needed(db=session, mailbox=mailbox)

        root_logger.removeHandler(captor)
        for record in captor.records:
            self.assertNotIn(secret, record, "Credential token leaked in log record!")
