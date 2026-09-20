"""
Unit and integration tests for Post-Final Production Optimization:
- Deterministic ML model loading & warm-up
- ML health diagnostics endpoint
- Real-time event broadcaster for sub-200ms updates
- Production frontend copy hygiene (zero demo UI/controls)
"""

import asyncio
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.services.event_broadcaster import (
    MailboxEventBroadcaster,
    broadcast_mailbox_event,
    get_event_broadcaster,
)
from ml.inference.loader import ModelLoader, get_default_loader, get_ml_health


client = TestClient(app)


class TestMlDeterministicLoading:
    """Validate that ML model and tokenizer load once, remain warm, and reuse instances."""

    def test_singleton_loader_instance(self) -> None:
        loader1 = get_default_loader()
        loader2 = get_default_loader()
        assert loader1 is loader2

    def test_ml_health_schema_and_path_safety(self) -> None:
        """Ensure /api/ml/health provides safe status without leaking local file paths or secrets."""
        response = client.get("/api/ml/health")
        assert response.status_code == 200
        data = response.json()

        assert "status" in data
        assert "model" in data
        assert "loaded" in data
        assert "device" in data
        assert "warm" in data
        assert "metrics" in data
        assert isinstance(data["metrics"], dict)

        # Confirm no path leakage (e.g. /Users/...)
        raw_text = response.text.lower()
        assert "/users/" not in raw_text
        assert "/home/" not in raw_text
        assert "token" not in raw_text
        assert "secret" not in raw_text

    def test_loader_cache_and_warmup(self) -> None:
        loader = ModelLoader()
        assert not loader.is_loaded()

        # Mock successful load to test singleton caching & warmup
        mock_model = MagicMock()
        mock_tokenizer = MagicMock()
        mock_inputs = {"input_ids": MagicMock()}
        mock_tokenizer.return_value = mock_inputs
        mock_model.return_value = MagicMock(logits=MagicMock())

        with patch.object(loader, "_load_internal", return_value=(mock_model, mock_tokenizer)):
            # First load
            m1, t1 = loader.load()
            assert loader.is_loaded()
            assert m1 is mock_model
            assert t1 is mock_tokenizer

            # Subsequent load must return cached instances without reloading
            m2, t2 = loader.load()
            assert m2 is m1
            assert t2 is t1

            # Warmup
            with patch("torch.no_grad"):
                success = loader.warm_up()
                assert success is True
                health = loader.get_health()
                assert health["loaded"] is True
                assert health["warm"] is True

            # Record inference latency
            loader.record_inference_latency(14.5)
            health = loader.get_health()
            assert health["metrics"]["last_inference_latency_ms"] == 14.5

            # Clear cache
            loader.clear_cache()
            assert not loader.is_loaded()
            assert loader.get_health()["loaded"] is False


class TestRealtimeEventBroadcaster:
    """Validate in-memory event dispatching for near-instantaneous UI updates."""

    def test_broadcaster_event_delivery(self) -> None:
        broadcaster = MailboxEventBroadcaster()
        mailbox_id = 999

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            queue = asyncio.Queue()
            loop.run_until_complete(broadcaster._add_subscriber(mailbox_id, queue))
            assert broadcaster.subscriber_count(mailbox_id) == 1

            # Broadcast new alert event
            alert_payload = {"alert_id": "alt_test_1", "verdict": "MALICIOUS", "risk_score": 85}
            delivered = broadcaster.broadcast(
                mailbox_id=mailbox_id,
                event_type="NEW_ALERT",
                payload={"alert": alert_payload},
            )
            assert delivered == 1

            # Retrieve event from subscriber queue
            item = queue.get_nowait()
            data = json.loads(item)
            assert data["type"] == "NEW_ALERT"
            assert data["mailbox_id"] == mailbox_id
            assert data["payload"]["alert"]["alert_id"] == "alt_test_1"

            # Cleanup
            loop.run_until_complete(broadcaster._remove_subscriber(mailbox_id, queue))
            assert broadcaster.subscriber_count(mailbox_id) == 0
        finally:
            loop.close()

    def test_global_broadcaster_helper(self) -> None:
        delivered = broadcast_mailbox_event(
            mailbox_id=888,
            event_type="MESSAGE_REMEDIATED",
            payload={"action": "REPORT_SPAM", "message_id": "msg_001"},
        )
        assert delivered == 0  # No listeners connected, non-blocking zero return


class TestProductionFrontendHygiene:
    """Audit frontend source code to ensure zero user-facing demo/simulation controls."""

    def test_frontend_has_no_demo_scenarios_or_controls(self) -> None:
        repo_root = Path(__file__).resolve().parents[2]
        app_tsx_path = repo_root / "frontend" / "App.tsx"
        assert app_tsx_path.is_file(), f"Missing App.tsx at {app_tsx_path}"

        content = app_tsx_path.read_text(encoding="utf-8")

        # Must not contain demo scenario declarations or shortcuts
        assert "const DEMO_SCENARIOS" not in content
        assert "demoToPreScan" not in content
        assert "handleSimulateDemoEvent" not in content
        assert "⚡ Demo Threat Event" not in content
        assert "⚡ Demo" not in content
        assert "TEST DEMO SECURITY PREVIEWS" not in content
        assert "TEST PRE-OPEN SECURITY PREVIEWS (OFFLINE)" not in content
        assert "QUICK DEMO SCENARIOS" not in content
        assert "(Demo mode only)" not in content


class TestSecurityKeyConfigValidation:
    """Validate that SECRET_KEY is strictly enforced and required in production."""

    def test_development_default_secret_key_allowed(self) -> None:
        from backend.app.core.config import Settings
        with patch.dict("os.environ", {"APP_ENV": "development"}):
            cfg = Settings(secret_key="your-random-secret-key", app_env="development")
            assert cfg.secret_key == "your-random-secret-key"

    def test_production_rejects_default_secret_key(self) -> None:
        from backend.app.core.config import Settings
        with patch.dict("os.environ", {"APP_ENV": "production"}):
            with pytest.raises(ValueError, match="SECRET_KEY must be provided via a real environment variable"):
                Settings(secret_key="your-random-secret-key", app_env="production")

    def test_production_accepts_secure_custom_key(self) -> None:
        from backend.app.core.config import Settings
        with patch.dict("os.environ", {"APP_ENV": "production"}):
            cfg = Settings(secret_key="custom_prod_sec_key_998877", app_env="production")
            assert cfg.secret_key == "custom_prod_sec_key_998877"

