"""Tests for Part 3 Analysis Pipeline Orchestration and Ingestion."""

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
from backend.app.models.enums import CaseStatus
from backend.app.schemas.analysis import NormalizedEmail
from backend.app.services.analysis_pipeline import AnalysisPipeline, get_pipeline
from backend.app.services.stages.base import BaseAnalysisStage


class FaultyStage(BaseAnalysisStage):
    """Test stage simulating an internal unhandled exception."""

    stage_name = "forensics"

    def analyze(self, email: NormalizedEmail, context: Dict[str, Any]) -> Dict[str, Any]:
        raise RuntimeError("Simulated internal stage error")


class AnalysisPipelineTestCase(unittest.TestCase):
    """Test suite for Part 3 Analysis Pipeline requirements."""

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
        """Re-create clean tables for each test."""
        Base.metadata.drop_all(bind=self.test_engine)
        init_db(engine=self.test_engine)

    def tearDown(self) -> None:
        """Drop tables after each test and restore default pipeline."""
        app.dependency_overrides.pop(get_pipeline, None)
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

    # 1. Valid normalized email accepted
    def test_valid_normalized_email_accepted(self) -> None:
        payload = {
            "provider": "gmail",
            "provider_message_id": "test-msg-001",
            "thread_id": "thread-001",
            "sender": "external@partner.org",
            "recipient": "analyst@mailtrace.ai",
            "subject": "Security Review Documents",
            "body": "Please review the attached contract.",
            "headers": [{"name": "Return-Path", "value": "<external@partner.org>"}],
        }
        status_code, body = self.request("POST", "/api/analysis", payload)
        self.assertEqual(status_code, 200)
        self.assertIn("case_id", body)
        self.assertTrue(body["case_id"].startswith("case_"))
        self.assertEqual(body["status"], CaseStatus.PROCESSING.value)
        self.assertEqual(body["message"], "Analysis pipeline started")

    # 2. Invalid missing provider rejected
    def test_invalid_missing_provider_rejected(self) -> None:
        payload = {
            # provider missing
            "provider_message_id": "msg-002",
            "sender": "sender@example.com",
            "recipient": "recipient@example.com",
        }
        status_code, _ = self.request("POST", "/api/analysis", payload)
        self.assertEqual(status_code, 422)

    # 3. Invalid missing provider_message_id rejected
    def test_invalid_missing_provider_message_id_rejected(self) -> None:
        payload = {
            "provider": "gmail",
            # provider_message_id missing
            "sender": "sender@example.com",
            "recipient": "recipient@example.com",
        }
        status_code, _ = self.request("POST", "/api/analysis", payload)
        self.assertEqual(status_code, 422)

    # 4. Invalid missing sender rejected
    def test_invalid_missing_sender_rejected(self) -> None:
        payload = {
            "provider": "gmail",
            "provider_message_id": "msg-004",
            # sender missing
            "recipient": "recipient@example.com",
        }
        status_code, _ = self.request("POST", "/api/analysis", payload)
        self.assertEqual(status_code, 422)

    # 5. Analysis creates a case
    def test_analysis_creates_case(self) -> None:
        payload = {
            "provider": "gmail",
            "provider_message_id": "msg-new-case",
            "sender": "new-sender@example.com",
            "recipient": "receiver@example.com",
            "subject": "New Threat Analysis",
        }
        status_code, start_resp = self.request("POST", "/api/analysis", payload)
        self.assertEqual(status_code, 200)
        case_id = start_resp["case_id"]

        # Fetch case through case API
        status_code, case_resp = self.request("GET", f"/api/cases/{case_id}")
        self.assertEqual(status_code, 200)
        self.assertEqual(case_resp["case_id"], case_id)
        self.assertEqual(case_resp["provider"], "gmail")
        self.assertEqual(case_resp["provider_message_id"], "msg-new-case")
        self.assertEqual(case_resp["status"], CaseStatus.PROCESSING.value)

    # 6. Existing case can be reused
    def test_existing_case_reused(self) -> None:
        payload = {
            "provider": "gmail",
            "provider_message_id": "duplicate-msg-id",
            "sender": "sender@domain.com",
            "recipient": "user@domain.com",
            "subject": "Initial run",
        }
        status_code, first_resp = self.request("POST", "/api/analysis", payload)
        self.assertEqual(status_code, 200)
        first_case_id = first_resp["case_id"]

        # Re-post with same provider and provider_message_id
        payload["subject"] = "Subsequent run with same message ID"
        status_code, second_resp = self.request("POST", "/api/analysis", payload)
        self.assertEqual(status_code, 200)
        second_case_id = second_resp["case_id"]

        self.assertEqual(first_case_id, second_case_id)

    # 7. Case status changes to PROCESSING
    def test_case_status_changes_to_processing(self) -> None:
        # Pre-create case via case API in NEW status
        _, created_case = self.request("POST", "/api/cases", {
            "provider": "outlook",
            "provider_message_id": "outlook-msg-123",
            "sender": "someone@outlook.com",
            "recipient": "target@corp.com",
            "subject": "Outlook Invoice",
            "received_at": "2026-09-19T10:00:00Z",
        })
        self.assertEqual(created_case["status"], CaseStatus.NEW.value)

        # Trigger analysis pipeline for same message
        status_code, start_resp = self.request("POST", "/api/analysis", {
            "provider": "outlook",
            "provider_message_id": "outlook-msg-123",
            "sender": "someone@outlook.com",
            "recipient": "target@corp.com",
            "subject": "Outlook Invoice",
        })
        self.assertEqual(status_code, 200)
        self.assertEqual(start_resp["status"], CaseStatus.PROCESSING.value)

        # Verify case in database is now PROCESSING
        status_code, case_resp = self.request("GET", f"/api/cases/{created_case['case_id']}")
        self.assertEqual(status_code, 200)
        self.assertEqual(case_resp["status"], CaseStatus.PROCESSING.value)

    # 8. Structured analysis result returned
    def test_structured_analysis_result_returned(self) -> None:
        payload = {
            "provider": "gmail",
            "provider_message_id": "msg-stages-test",
            "sender": "sender@test.com",
            "recipient": "receiver@test.com",
            "subject": "Stage Verification",
            "body": "Hello world",
        }
        status_code, start_resp = self.request("POST", "/api/analysis", payload)
        self.assertEqual(status_code, 200)
        case_id = start_resp["case_id"]

        # Fetch analysis for case
        status_code, analyses = self.request("GET", f"/api/cases/{case_id}/analysis")
        self.assertEqual(status_code, 200)
        self.assertIsInstance(analyses, list)
        self.assertGreaterEqual(len(analyses), 1)

        latest_analysis = analyses[0]
        # Verify presence of all required stage keys
        required_stages = ["forensics", "authentication", "ml", "intelligence", "correlation", "risk"]
        for stage in required_stages:
            self.assertIn(stage, latest_analysis)
            self.assertIsInstance(latest_analysis[stage], dict)
            self.assertIn(latest_analysis[stage].get("status"), ("not_implemented", "completed"))

    # 9. Audit event is recorded
    def test_audit_event_recorded(self) -> None:
        payload = {
            "provider": "gmail",
            "provider_message_id": "msg-audit-test-pipeline",
            "sender": "sender@test.com",
            "recipient": "receiver@test.com",
            "subject": "Audit Trail Pipeline Test",
        }
        status_code, start_resp = self.request("POST", "/api/analysis", payload)
        self.assertEqual(status_code, 200)
        case_id = start_resp["case_id"]

        status_code, audit_events = self.request("GET", f"/api/cases/{case_id}/audit")
        self.assertEqual(status_code, 200)
        event_types = [e["event_type"] for e in audit_events]
        self.assertIn("CASE_CREATED", event_types)
        self.assertIn("STATUS_UPDATED", event_types)
        self.assertIn("PIPELINE_EXECUTED", event_types)

    # 10. Analysis endpoint does not require file upload
    def test_analysis_does_not_require_file_upload(self) -> None:
        # Accepts direct JSON in-memory dictionary
        payload = {
            "provider": "gmail",
            "provider_message_id": "msg-in-memory-only",
            "sender": "sender@test.com",
            "recipient": "receiver@test.com",
            "subject": "Direct JSON Ingestion",
            "body": "No .eml file needed",
            "headers": ["Received: from mail.example.com"],
        }
        status_code, resp = self.request("POST", "/api/analysis", payload)
        self.assertEqual(status_code, 200)
        self.assertEqual(resp["status"], CaseStatus.PROCESSING.value)

    # 11. Individual stage failure resilience
    def test_stage_failure_resilience(self) -> None:
        # Inject custom pipeline with a failing forensics stage
        faulty_pipeline = AnalysisPipeline(forensics=FaultyStage())
        app.dependency_overrides[get_pipeline] = lambda: faulty_pipeline

        payload = {
            "provider": "gmail",
            "provider_message_id": "msg-fault-tolerance",
            "sender": "sender@test.com",
            "recipient": "receiver@test.com",
            "subject": "Fault Tolerance Test",
        }
        status_code, start_resp = self.request("POST", "/api/analysis", payload)
        self.assertEqual(status_code, 200)
        case_id = start_resp["case_id"]

        # Check analysis result captured error for forensics, but other stages succeeded
        status_code, analyses = self.request("GET", f"/api/cases/{case_id}/analysis")
        self.assertEqual(status_code, 200)
        self.assertEqual(analyses[0]["forensics"]["status"], "error")
        self.assertIn("Simulated internal stage error", analyses[0]["forensics"]["error"])
        self.assertEqual(analyses[0]["authentication"]["status"], "not_implemented")

        # Check audit event was recorded for stage error
        status_code, audit_events = self.request("GET", f"/api/cases/{case_id}/audit")
        self.assertEqual(status_code, 200)
        event_types = [e["event_type"] for e in audit_events]
        self.assertIn("STAGE_ERROR_FORENSICS", event_types)


if __name__ == "__main__":
    unittest.main()
