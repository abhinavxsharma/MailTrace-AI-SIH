"""Integration and unit tests for database and case management layer."""

import asyncio
import json
import unittest
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlparse

from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.db.database import Base, init_db
from backend.app.db.session import get_db
from backend.app.main import app
from backend.app.models.enums import CaseStatus, Classification, MailboxStatus


class CaseManagementTestCase(unittest.TestCase):
    """Test suite for Part 2 Database and Case Management requirements."""

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

    # 1. Health endpoint still works
    def test_health_endpoint_still_works(self) -> None:
        status_code, body = self.request("GET", "/api/health")
        self.assertEqual(status_code, 200)
        self.assertEqual(body, {"status": "ok", "service": "mailtrace-ai"})

    # 2. Database initializes
    def test_database_initialization(self) -> None:
        inspector = inspect(self.test_engine)
        tables = inspector.get_table_names()
        expected_tables = {"mailboxes", "cases", "analyses", "audit_events"}
        self.assertTrue(expected_tables.issubset(set(tables)))

    # 3. Create mailbox
    def test_create_mailbox(self) -> None:
        payload = {
            "provider": "gmail",
            "account_email": "security@mailtrace.ai",
            "status": "CONNECTED",
        }
        status_code, body = self.request("POST", "/api/mailboxes", payload)
        self.assertEqual(status_code, 201)
        self.assertEqual(body["provider"], "gmail")
        self.assertEqual(body["account_email"], "security@mailtrace.ai")
        self.assertEqual(body["status"], "CONNECTED")
        self.assertIn("id", body)

    # 4. List mailboxes
    def test_list_mailboxes(self) -> None:
        self.request("POST", "/api/mailboxes", {"provider": "gmail", "account_email": "user1@example.com"})
        self.request("POST", "/api/mailboxes", {"provider": "outlook", "account_email": "user2@example.com"})

        status_code, body = self.request("GET", "/api/mailboxes")
        self.assertEqual(status_code, 200)
        self.assertIsInstance(body, list)
        self.assertEqual(len(body), 2)

    # 5. Create case
    def test_create_case(self) -> None:
        # Register a mailbox first
        _, mb = self.request("POST", "/api/mailboxes", {"provider": "gmail", "account_email": "user@example.com"})

        payload = {
            "provider": "gmail",
            "provider_message_id": "msg-101",
            "thread_id": "thread-202",
            "sender": "attacker@phish.net",
            "recipient": "user@example.com",
            "subject": "Urgent Invoice Payment",
            "received_at": "2026-09-19T10:00:00Z",
            "mailbox_id": mb["id"],
        }
        status_code, body = self.request("POST", "/api/cases", payload)
        self.assertEqual(status_code, 201)
        self.assertTrue(body["case_id"].startswith("case_"))
        self.assertEqual(body["provider_message_id"], "msg-101")
        self.assertEqual(body["status"], CaseStatus.NEW.value)
        self.assertEqual(body["classification"], Classification.PENDING.value)
        self.assertIsNone(body["risk_score"])

    # 6. Get case
    def test_get_case(self) -> None:
        payload = {
            "provider": "gmail",
            "provider_message_id": "msg-102",
            "sender": "boss@corp.com",
            "recipient": "employee@corp.com",
            "subject": "Quarterly Update",
            "received_at": "2026-09-19T10:30:00Z",
        }
        _, created = self.request("POST", "/api/cases", payload)
        case_id = created["case_id"]

        status_code, body = self.request("GET", f"/api/cases/{case_id}")
        self.assertEqual(status_code, 200)
        self.assertEqual(body["case_id"], case_id)
        self.assertEqual(body["subject"], "Quarterly Update")

    # 7. List cases
    def test_list_cases(self) -> None:
        for i in range(3):
            self.request("POST", "/api/cases", {
                "provider": "gmail",
                "provider_message_id": f"msg-{i}",
                "sender": f"sender{i}@test.com",
                "recipient": "receiver@test.com",
                "subject": f"Subject {i}",
                "received_at": "2026-09-19T11:00:00Z",
            })

        status_code, body = self.request("GET", "/api/cases?limit=2")
        self.assertEqual(status_code, 200)
        self.assertEqual(len(body), 2)

    # 8. Update case status
    def test_update_case_status(self) -> None:
        _, created = self.request("POST", "/api/cases", {
            "provider": "gmail",
            "provider_message_id": "msg-status-test",
            "sender": "sender@test.com",
            "recipient": "receiver@test.com",
            "subject": "Status check",
            "received_at": "2026-09-19T12:00:00Z",
        })
        case_id = created["case_id"]

        status_code, body = self.request(
            "PATCH",
            f"/api/cases/{case_id}/status",
            {"status": CaseStatus.PROCESSING.value},
        )
        self.assertEqual(status_code, 200)
        self.assertEqual(body["status"], CaseStatus.PROCESSING.value)

    # 9. Update case analysis result
    def test_update_case_analysis_result(self) -> None:
        _, created = self.request("POST", "/api/cases", {
            "provider": "gmail",
            "provider_message_id": "msg-analysis-test",
            "sender": "phisher@bad.com",
            "recipient": "victim@domain.com",
            "subject": "Suspicious login alert",
            "received_at": "2026-09-19T12:30:00Z",
        })
        case_id = created["case_id"]

        result_payload = {
            "classification": Classification.MALICIOUS.value,
            "ai_confidence": 0.96,
            "risk_score": 88,
        }
        status_code, body = self.request(
            "PATCH",
            f"/api/cases/{case_id}/result",
            result_payload,
        )
        self.assertEqual(status_code, 200)
        self.assertEqual(body["classification"], Classification.MALICIOUS.value)
        self.assertEqual(body["ai_confidence"], 0.96)
        self.assertEqual(body["risk_score"], 88)
        self.assertEqual(body["status"], CaseStatus.COMPLETED.value)

        # Verify analysis record was persisted
        status_code, analyses = self.request("GET", f"/api/cases/{case_id}/analysis")
        self.assertEqual(status_code, 200)
        self.assertEqual(len(analyses), 1)
        self.assertEqual(analyses[0]["classification"], Classification.MALICIOUS.value)
        self.assertEqual(analyses[0]["risk_score"], 88)

    # 10. Retrieve audit events
    def test_retrieve_audit_events(self) -> None:
        _, created = self.request("POST", "/api/cases", {
            "provider": "gmail",
            "provider_message_id": "msg-audit-test",
            "sender": "sender@test.com",
            "recipient": "receiver@test.com",
            "subject": "Audit Trail Check",
            "received_at": "2026-09-19T13:00:00Z",
        })
        case_id = created["case_id"]

        # Update status to trigger another audit event
        self.request("PATCH", f"/api/cases/{case_id}/status", {"status": CaseStatus.PROCESSING.value})

        status_code, audit_events = self.request("GET", f"/api/cases/{case_id}/audit")
        self.assertEqual(status_code, 200)
        self.assertGreaterEqual(len(audit_events), 2)
        event_types = [e["event_type"] for e in audit_events]
        self.assertIn("CASE_CREATED", event_types)
        self.assertIn("STATUS_UPDATED", event_types)

    # 11. Invalid risk score is rejected
    def test_invalid_risk_score_rejected(self) -> None:
        _, created = self.request("POST", "/api/cases", {
            "provider": "gmail",
            "provider_message_id": "msg-validation-risk",
            "sender": "sender@test.com",
            "recipient": "receiver@test.com",
            "subject": "Validation Test",
            "received_at": "2026-09-19T13:30:00Z",
        })
        case_id = created["case_id"]

        # Risk score > 100
        status_code, body = self.request("PATCH", f"/api/cases/{case_id}/result", {
            "classification": Classification.BENIGN.value,
            "risk_score": 105,
        })
        self.assertEqual(status_code, 422)

        # Risk score < 0
        status_code, body = self.request("PATCH", f"/api/cases/{case_id}/result", {
            "classification": Classification.BENIGN.value,
            "risk_score": -10,
        })
        self.assertEqual(status_code, 422)

    # 12. Invalid AI confidence is rejected
    def test_invalid_ai_confidence_rejected(self) -> None:
        _, created = self.request("POST", "/api/cases", {
            "provider": "gmail",
            "provider_message_id": "msg-validation-conf",
            "sender": "sender@test.com",
            "recipient": "receiver@test.com",
            "subject": "Confidence Validation Test",
            "received_at": "2026-09-19T13:30:00Z",
        })
        case_id = created["case_id"]

        # AI confidence > 1.0
        status_code, body = self.request("PATCH", f"/api/cases/{case_id}/result", {
            "classification": Classification.BENIGN.value,
            "ai_confidence": 1.25,
        })
        self.assertEqual(status_code, 422)

        # AI confidence < 0.0
        status_code, body = self.request("PATCH", f"/api/cases/{case_id}/result", {
            "classification": Classification.BENIGN.value,
            "ai_confidence": -0.5,
        })
        self.assertEqual(status_code, 422)

    # 13. Missing provider message ID is rejected
    def test_missing_provider_message_id_rejected(self) -> None:
        payload = {
            "provider": "gmail",
            # provider_message_id missing
            "sender": "sender@test.com",
            "recipient": "receiver@test.com",
            "subject": "Missing Message ID",
            "received_at": "2026-09-19T13:30:00Z",
        }
        status_code, body = self.request("POST", "/api/cases", payload)
        self.assertEqual(status_code, 422)

    # 14. Invalid status value is rejected
    def test_invalid_status_rejected(self) -> None:
        _, created = self.request("POST", "/api/cases", {
            "provider": "gmail",
            "provider_message_id": "msg-invalid-status",
            "sender": "sender@test.com",
            "recipient": "receiver@test.com",
            "subject": "Status check",
            "received_at": "2026-09-19T13:30:00Z",
        })
        case_id = created["case_id"]

        status_code, body = self.request("PATCH", f"/api/cases/{case_id}/status", {"status": "NOT_A_STATUS"})
        self.assertEqual(status_code, 422)

    # 15. Invalid classification value is rejected
    def test_invalid_classification_rejected(self) -> None:
        _, created = self.request("POST", "/api/cases", {
            "provider": "gmail",
            "provider_message_id": "msg-invalid-class",
            "sender": "sender@test.com",
            "recipient": "receiver@test.com",
            "subject": "Classification check",
            "received_at": "2026-09-19T13:30:00Z",
        })
        case_id = created["case_id"]

        status_code, body = self.request("PATCH", f"/api/cases/{case_id}/result", {
            "classification": "SUPER_MALICIOUS",
        })
        self.assertEqual(status_code, 422)

    # 16. Case ID uniqueness
    def test_case_id_uniqueness(self) -> None:
        ids = set()
        for i in range(10):
            _, created = self.request("POST", "/api/cases", {
                "provider": "gmail",
                "provider_message_id": f"msg-uniq-{i}",
                "sender": "sender@test.com",
                "recipient": "receiver@test.com",
                "subject": f"Uniqueness check {i}",
                "received_at": "2026-09-19T13:30:00Z",
            })
            self.assertNotIn(created["case_id"], ids)
            ids.add(created["case_id"])
        self.assertEqual(len(ids), 10)


if __name__ == "__main__":
    unittest.main()

