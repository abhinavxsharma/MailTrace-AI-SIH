"""Unit and integration tests for Part 6 Backend Hardening."""

import asyncio
import json
import unittest
from typing import Any, Dict, Optional, Tuple
from unittest.mock import MagicMock
from urllib.parse import urlparse

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.db.database import Base, init_db
from backend.app.db.session import get_db
from backend.app.main import app
from backend.app.models.mailbox import Mailbox


class BackendHardeningTestCase(unittest.TestCase):
    """Test suite covering Part 6 Backend Hardening requirements."""

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

        # Add a temporary test endpoint to trigger an unhandled internal exception
        @app.get("/api/test-internal-error", tags=["testing"])
        def raise_unhandled_error():
            raise RuntimeError("Database credentials leaked: supersecret_pw_123")

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
        """Perform an HTTP request directly against the ASGI app, capturing status, body, and headers."""
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

    # 1. Request ID header is automatically generated and returned
    def test_response_includes_request_id(self) -> None:
        status_code, body, headers = self.request("GET", "/api/health")
        self.assertEqual(status_code, 200)
        self.assertIn("x-request-id", headers)
        self.assertTrue(headers["x-request-id"].startswith("req_"))

    # 2. Supplied valid Request ID is preserved
    def test_supplied_valid_request_id_preserved(self) -> None:
        custom_id = "test-custom-req-id-12345"
        status_code, body, headers = self.request(
            "GET",
            "/api/health",
            headers_dict={"X-Request-ID": custom_id},
        )
        self.assertEqual(status_code, 200)
        self.assertEqual(headers.get("x-request-id"), custom_id)

    # 3. Unsafe / malformed Request ID is sanitized and replaced
    def test_unsafe_request_id_sanitized(self) -> None:
        malicious_id = "<script>alert('xss')</script>"
        status_code, body, headers = self.request(
            "GET",
            "/api/health",
            headers_dict={"X-Request-ID": malicious_id},
        )
        self.assertEqual(status_code, 200)
        returned_id = headers.get("x-request-id")
        self.assertNotEqual(returned_id, malicious_id)
        self.assertTrue(returned_id.startswith("req_"))

    # 4. Health endpoint works
    def test_health_endpoint(self) -> None:
        status_code, body, headers = self.request("GET", "/api/health")
        self.assertEqual(status_code, 200)
        self.assertEqual(body["status"], "ok")
        self.assertEqual(body["service"], "mailtrace-ai")

    # 5. Readiness probe succeeds with operational database
    def test_readiness_endpoint_success(self) -> None:
        status_code, body, headers = self.request("GET", "/api/ready")
        self.assertEqual(status_code, 200)
        self.assertEqual(body["status"], "ready")
        self.assertEqual(body["database"], "ok")

    # 6. Readiness probe handles database failure safely
    def test_readiness_endpoint_db_failure(self) -> None:
        mock_db = MagicMock()
        mock_db.execute.side_effect = RuntimeError("SQLite disk I/O failure")

        def broken_get_db():
            yield mock_db

        app.dependency_overrides[get_db] = broken_get_db
        try:
            status_code, body, headers = self.request("GET", "/api/ready")
            self.assertEqual(status_code, 503)
            self.assertEqual(body["status"], "not_ready")
            self.assertEqual(body["database"], "error")
            self.assertEqual(body["error"]["code"], "DATABASE_UNAVAILABLE")
        finally:
            def restore_get_db():
                db = self.TestingSessionLocal()
                try:
                    yield db
                finally:
                    db.close()
            app.dependency_overrides[get_db] = restore_get_db

    # 7. Unknown route returns consistent 404 error envelope
    def test_unknown_route_consistent_error(self) -> None:
        status_code, body, headers = self.request("GET", "/api/nonexistent-route-xyz")
        self.assertEqual(status_code, 404)
        self.assertIn("error", body)
        self.assertEqual(body["error"]["code"], "NOT_FOUND")
        self.assertIn("message", body["error"])

    # 8. Request validation errors return consistent 422 error envelope
    def test_validation_error_consistent_envelope(self) -> None:
        status_code, body, headers = self.request("POST", "/api/cases", data={})
        self.assertEqual(status_code, 422)
        self.assertIn("error", body)
        self.assertEqual(body["error"]["code"], "VALIDATION_ERROR")
        self.assertIn("details", body["error"])

    # 9. Unhandled internal exceptions do not expose stack traces or secrets
    def test_internal_exception_does_not_expose_stack_trace(self) -> None:
        status_code, body, headers = self.request("GET", "/api/test-internal-error")
        self.assertEqual(status_code, 500)
        self.assertIn("error", body)
        self.assertEqual(body["error"]["code"], "INTERNAL_SERVER_ERROR")
        # Ensure secret message and traceback are not leaked in the client payload
        self.assertNotIn("supersecret_pw_123", json.dumps(body))
        self.assertNotIn("Traceback", json.dumps(body))

    # 10. Existing case APIs still work and include X-Request-ID
    def test_existing_case_apis_still_work(self) -> None:
        payload = {
            "provider": "gmail",
            "provider_message_id": "hardening-case-001",
            "sender": "sender@external.com",
            "recipient": "analyst@mailtrace.ai",
            "subject": "Hardening Verification",
            "received_at": "2026-09-19T10:00:00Z",
        }
        status_code, body, headers = self.request("POST", "/api/cases", data=payload)
        self.assertEqual(status_code, 201)
        self.assertIn("case_id", body)
        self.assertIn("x-request-id", headers)

    # 11. Existing analysis API still works and includes X-Request-ID
    def test_existing_analysis_api_still_work(self) -> None:
        email_payload = {
            "provider": "gmail",
            "provider_message_id": "hardening-msg-002",
            "sender": "alerts@service.internal",
            "recipient": "security@mailtrace.ai",
            "subject": "Pipeline Hardening Test",
            "headers": [],
            "body": "Test analysis content",
        }
        status_code, body, headers = self.request("POST", "/api/analysis", data=email_payload)
        self.assertEqual(status_code, 200)
        self.assertIn("case_id", body)
        self.assertIn("x-request-id", headers)

    # 12. Existing mail event API still works and includes X-Request-ID
    def test_existing_mail_event_api_still_work(self) -> None:
        # Register mailbox first
        with self.TestingSessionLocal() as session:
            mailbox = Mailbox(
                account_email="analyst@mailtrace.ai",
                provider="gmail",
                status="ACTIVE",
            )
            session.add(mailbox)
            session.commit()

        event_payload = {
            "provider": "gmail",
            "account_email": "analyst@mailtrace.ai",
            "provider_message_id": "hardening-event-003",
            "event_type": "NEW_MESSAGE",
        }
        status_code, body, headers = self.request("POST", "/api/mail/events", data=event_payload)
        self.assertEqual(status_code, 200)
        self.assertEqual(body["status"], "accepted")
        self.assertIn("x-request-id", headers)


if __name__ == "__main__":
    unittest.main()
