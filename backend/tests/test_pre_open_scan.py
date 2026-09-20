"""
Unit and integration tests for Pre-Open Threat Detection Foundation (Chunk 1/5).

Validates:
- Benign email pre-open scan (low risk, clean verdict, explainable reasons)
- Malicious BEC and phishing pre-open scan (high risk, mismatch & lure indicators)
- Resilience with missing optional headers (subject, date, body)
- ML model unavailable / fallback behavior
- Verification of response schema contract (reasons, indicators, auth summary)
- API endpoint execution (POST /api/mailboxes/{id}/messages/{id}/pre-scan)
- 404 for invalid mailbox and 400 for unsupported provider
- Zero raw email disk persistence guarantee
"""

import asyncio
import json
import os
import unittest
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Tuple
from unittest.mock import MagicMock, patch
from urllib.parse import urlparse

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.db.database import Base, init_db
from backend.app.db.session import get_db
from backend.app.main import app
from backend.app.models.enums import Classification, MailboxStatus
from backend.app.models.mailbox import Mailbox
from backend.app.schemas.analysis import NormalizedEmail
from backend.app.schemas.pre_open import PreOpenScanResponse
from backend.app.services.pre_open_scan import scan_email_pre_open
from backend.app.services.risk.levels import RiskLevel
from ml.inference.models import ClassificationLabel, MlClassificationResult


class PreOpenScanTestCase(unittest.TestCase):
    """Test suite validating the fast in-memory Pre-Open Email Threat Scan."""

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

    # -------------------------------------------------------------------------
    # Core Service Unit Tests
    # -------------------------------------------------------------------------

    def test_benign_pre_open_message(self) -> None:
        """Verify clean internal business message produces BENIGN verdict and low risk score."""
        email = NormalizedEmail(
            provider="gmail",
            provider_message_id="msg-benign-001",
            thread_id="thread-001",
            sender="Finance Team <finance@company-internal.org>",
            recipient="employee@company-internal.org",
            subject="Monthly expense report — September",
            body="Hello team, the September expense report is ready. Please review it on the internal portal.",
            headers=[
                {"name": "From", "value": "Finance Team <finance@company-internal.org>"},
                {"name": "To", "value": "employee@company-internal.org"},
                {"name": "Reply-To", "value": "finance@company-internal.org"},
                {"name": "Return-Path", "value": "<finance@company-internal.org>"},
                {
                    "name": "Authentication-Results",
                    "value": "mx.google.com; spf=pass; dkim=pass; dmarc=pass header.from=company-internal.org",
                },
            ],
            received_at=datetime(2026, 9, 20, 10, 0, tzinfo=timezone.utc),
        )

        res = scan_email_pre_open(email)

        self.assertIsInstance(res, PreOpenScanResponse)
        self.assertEqual(res.message_id, "msg-benign-001")
        self.assertEqual(res.thread_id, "thread-001")
        self.assertEqual(res.sender, "finance@company-internal.org")
        self.assertEqual(res.sender_name, "Finance Team")
        self.assertEqual(res.verdict, Classification.BENIGN)
        self.assertLessEqual(res.risk_score, 39)
        self.assertEqual(res.risk_level, RiskLevel.LOW)
        self.assertEqual(res.authentication_summary.spf, "PASS")
        self.assertEqual(res.authentication_summary.dkim, "PASS")
        self.assertEqual(res.authentication_summary.dmarc, "PASS")
        self.assertTrue(res.authentication_summary.authenticated)
        self.assertTrue(res.can_investigate)
        self.assertIn("Safe to preview", res.recommended_action)
        self.assertTrue(any("Cryptographic authentication" in r or "Clean threat profile" in r for r in res.reasons))

    def test_malicious_bec_fraud_pre_open_message(self) -> None:
        """Verify BEC email with CFO impersonation, Reply-To mismatch, and wire transfer lure triggers MALICIOUS."""
        email = NormalizedEmail(
            provider="gmail",
            provider_message_id="msg-bec-999",
            thread_id="thread-999",
            sender="Chief Financial Officer <cfo@acme-corp.com>",
            recipient="accounts@target-company.com",
            subject="URGENT: Executive Wire Transfer Instructions — Process Immediately",
            body="Please execute this urgent wire transfer of $185,000 immediately to the attached account.",
            headers=[
                {"name": "From", "value": "Chief Financial Officer <cfo@acme-corp.com>"},
                {"name": "To", "value": "accounts@target-company.com"},
                {"name": "Reply-To", "value": "attacker-cfo@external-fraud-box.net"},
                {"name": "Return-Path", "value": "<bounce@attacker-host.com>"},
                {
                    "name": "Authentication-Results",
                    "value": "mx.google.com; spf=fail; dkim=none; dmarc=fail action=none",
                },
            ],
            received_at=datetime.now(timezone.utc),
        )

        res = scan_email_pre_open(email)

        self.assertIsInstance(res, PreOpenScanResponse)
        self.assertEqual(res.verdict, Classification.MALICIOUS)
        self.assertGreaterEqual(res.risk_score, 40)
        self.assertIn(res.risk_level, (RiskLevel.HIGH, RiskLevel.CRITICAL, RiskLevel.MEDIUM))
        self.assertEqual(res.authentication_summary.spf, "FAIL")
        self.assertEqual(res.authentication_summary.dmarc, "FAIL")
        self.assertFalse(res.authentication_summary.authenticated)

        # Verify explainable reasons
        reasons_text = " ".join(res.reasons)
        self.assertIn("Reply-To", reasons_text)
        self.assertIn("wire transfer", reasons_text.lower())
        self.assertIn("urgency", reasons_text.lower())

        # Verify indicators
        self.assertIn("IDENTITY_REPLY_TO_MISMATCH", res.indicators)
        self.assertIn("LURE_FINANCIAL_REQUEST", res.indicators)
        self.assertIn("LURE_HIGH_URGENCY", res.indicators)

        # Verify recommended action
        self.assertIn("Do not open", res.recommended_action)

    def test_credential_harvesting_phishing_pre_open_message(self) -> None:
        """Verify credential phishing lure with IP link is detected with clear explainable reason."""
        email = NormalizedEmail(
            provider="gmail",
            provider_message_id="msg-phish-404",
            sender="Security Team <admin@fake-security-alert.org>",
            recipient="user@target.com",
            subject="Your Account Has Been Suspended — Immediate Action Required",
            body="We noticed unauthorized activity. Please verify your account here: http://203.0.113.80/login",
            headers=[
                {"name": "From", "value": "Security Team <admin@fake-security-alert.org>"},
                {"name": "Authentication-Results", "value": "spf=fail; dkim=none; dmarc=fail"},
            ],
        )

        res = scan_email_pre_open(email)

        self.assertEqual(res.verdict, Classification.MALICIOUS)
        reasons_text = " ".join(res.reasons)
        self.assertIn("credential harvesting", reasons_text.lower())
        self.assertIn("LURE_CREDENTIAL_HARVESTING", res.indicators)
        self.assertIn("URL_IP_LITERAL_HOST", res.indicators)

    def test_missing_optional_headers_resilience(self) -> None:
        """Ensure scanning handles stripped emails (no subject, no date, minimal headers) gracefully."""
        email = NormalizedEmail(
            provider="gmail",
            provider_message_id="msg-minimal-000",
            sender="plain@example.com",
            recipient="test@example.com",
            subject="",
            body="",
            headers=[],
        )

        res = scan_email_pre_open(email)

        self.assertEqual(res.message_id, "msg-minimal-000")
        self.assertEqual(res.subject, "(No Subject)")
        self.assertEqual(res.sender, "plain@example.com")
        self.assertIsNone(res.sender_name)
        self.assertIsNotNone(res.received_at)
        self.assertEqual(res.authentication_summary.spf, "NONE")
        self.assertEqual(res.authentication_summary.dkim, "NONE")
        self.assertEqual(res.authentication_summary.dmarc, "NONE")
        self.assertFalse(res.authentication_summary.authenticated)
        self.assertIsInstance(res.risk_score, int)

    def test_ml_unavailable_fallback_behavior(self) -> None:
        """Verify that when ML classifier raises an exception, pre-open scan falls back gracefully."""
        email = NormalizedEmail(
            provider="gmail",
            provider_message_id="msg-ml-fallback",
            sender="hr@company-internal.org",
            recipient="all@company-internal.org",
            subject="Policy update reminder",
            body="Please review the employee handbook on the internal wiki.",
            headers=[
                {"name": "From", "value": "hr@company-internal.org"},
                {"name": "Authentication-Results", "value": "spf=pass; dkim=pass; dmarc=pass"},
            ],
        )

        with patch("ml.inference.classifier.classify_email", side_effect=RuntimeError("Weights offline")):
            res = scan_email_pre_open(email)

        self.assertIsInstance(res, PreOpenScanResponse)
        self.assertIsNone(res.confidence)
        # Without ML, authentication and heuristics still evaluate cleanly
        self.assertEqual(res.verdict, Classification.BENIGN)
        self.assertEqual(res.risk_level, RiskLevel.LOW)

    def test_zero_disk_persistence_guarantee(self) -> None:
        """Verify pre-open scan creates zero files on the local filesystem."""
        email = NormalizedEmail(
            provider="gmail",
            provider_message_id="msg-zero-disk-check",
            sender="auditor@security.org",
            recipient="victim@corp.com",
            subject="Auditing zero disk writes",
            body="This message content should remain strictly in memory.",
        )

        # Snapshot files in current working directory
        files_before = set(Path(".").glob("**/*"))

        scan_email_pre_open(email)

        files_after = set(Path(".").glob("**/*"))
        new_files = files_after - files_before

        # Ensure no .eml, .txt, or payload files were created
        unauthorized_files = [f for f in new_files if f.suffix in (".eml", ".txt", ".msg", ".tmp")]
        self.assertEqual(unauthorized_files, [])

    # -------------------------------------------------------------------------
    # API Endpoint Tests
    # -------------------------------------------------------------------------

    @patch("backend.app.services.gmail.client.TokenStore.get_credentials")
    @patch("backend.app.services.gmail.client.build_gmail_service")
    @patch("backend.app.services.gmail.client.fetch_gmail_message_resource")
    def test_api_pre_scan_endpoint_success(
        self,
        mock_fetch_resource: MagicMock,
        mock_build_svc: MagicMock,
        mock_get_creds: MagicMock,
    ) -> None:
        """Test POST /api/mailboxes/{mailbox_id}/messages/{message_id}/pre-scan returns valid schema."""
        # 1. Seed a connected mailbox
        with self.TestingSessionLocal() as session:
            mailbox = Mailbox(
                provider="gmail",
                account_email="prescan.tester@gmail.com",
                status=MailboxStatus.CONNECTED.value,
            )
            session.add(mailbox)
            session.commit()
            mailbox_id = mailbox.id

        # 2. Mock Gmail credentials and API response
        mock_get_creds.return_value = MagicMock()
        mock_build_svc.return_value = MagicMock()
        mock_fetch_resource.return_value = {
            "id": "gmail_msg_12345",
            "threadId": "thread_abcde",
            "internalDate": "1726830000000",
            "snippet": "Urgent invoice notification for review.",
            "payload": {
                "headers": [
                    {"name": "From", "value": "Billing Desk <billing@vendor.com>"},
                    {"name": "To", "value": "prescan.tester@gmail.com"},
                    {"name": "Subject", "value": "Invoice #8849 Attached"},
                    {"name": "Date", "value": "Sun, 20 Sep 2026 10:30:00 +0000"},
                    {"name": "Authentication-Results", "value": "mx.google.com; spf=pass; dkim=pass; dmarc=pass"},
                ],
                "body": {"size": 0},
                "parts": [
                    {
                        "mimeType": "text/plain",
                        "body": {"data": "SGVsbG8sIHBsZWFzZSBmaW5kIHlvdXIgaW52b2ljZSBmb3IgcmV2aWV3Lg=="},  # base64
                    }
                ],
            },
        }

        # 3. Call endpoint
        status_code, body = self.request(
            "POST",
            f"/api/mailboxes/{mailbox_id}/messages/gmail_msg_12345/pre-scan",
        )

        self.assertEqual(status_code, 200)
        self.assertEqual(body["message_id"], "gmail_msg_12345")
        self.assertEqual(body["thread_id"], "thread_abcde")
        self.assertEqual(body["sender"], "billing@vendor.com")
        self.assertEqual(body["sender_name"], "Billing Desk")
        self.assertEqual(body["subject"], "Invoice #8849 Attached")
        self.assertIn("verdict", body)
        self.assertIn("risk_score", body)
        self.assertIn("risk_level", body)
        self.assertIn("reasons", body)
        self.assertIn("indicators", body)
        self.assertIn("authentication_summary", body)
        self.assertEqual(body["authentication_summary"]["spf"], "PASS")
        self.assertEqual(body["authentication_summary"]["dmarc"], "PASS")
        self.assertTrue(body["can_investigate"])
        self.assertIn("recommended_action", body)

    def test_api_pre_scan_invalid_mailbox_404(self) -> None:
        """Test POST /api/mailboxes/99999/messages/msg_123/pre-scan returns 404."""
        status_code, body = self.request(
            "POST",
            "/api/mailboxes/99999/messages/msg_123/pre-scan",
        )
        self.assertEqual(status_code, 404)
        self.assertIn("Mailbox not found", body.get("detail", ""))

    def test_api_pre_scan_unsupported_provider_400(self) -> None:
        """Test POST pre-scan on a non-Gmail mailbox returns 400."""
        with self.TestingSessionLocal() as session:
            mailbox = Mailbox(
                provider="unsupported_imap",
                account_email="other@custom.org",
                status=MailboxStatus.CONNECTED.value,
            )
            session.add(mailbox)
            session.commit()
            mailbox_id = mailbox.id

        status_code, body = self.request(
            "POST",
            f"/api/mailboxes/{mailbox_id}/messages/msg_123/pre-scan",
        )
        self.assertEqual(status_code, 400)
        self.assertIn("not supported for provider", body.get("detail", ""))


if __name__ == "__main__":
    unittest.main()
