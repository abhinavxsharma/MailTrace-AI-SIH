"""Comprehensive tests for Part 4 Deterministic Risk Scoring Engine."""

import unittest
from backend.app.schemas.analysis import NormalizedEmail
from backend.app.services.risk.levels import RiskLevel, get_risk_level
from backend.app.services.risk.risk_engine import RiskEngine
from backend.app.services.risk.scoring import (
    score_ai_threat,
    score_authentication,
    score_campaign,
    score_identity,
    score_infrastructure,
    score_url_domain,
)
from backend.app.services.stages.risk import RiskService


class RiskEngineTestCase(unittest.TestCase):
    """Test suite for deterministic risk scoring and level mappings."""

    def setUp(self) -> None:
        self.engine = RiskEngine()

    # 1. Risk level boundary tests
    def test_risk_level_boundaries(self) -> None:
        self.assertEqual(get_risk_level(0), "LOW")
        self.assertEqual(get_risk_level(39), "LOW")
        self.assertEqual(get_risk_level(40), "MEDIUM")
        self.assertEqual(get_risk_level(69), "MEDIUM")
        self.assertEqual(get_risk_level(70), "HIGH")
        self.assertEqual(get_risk_level(84), "HIGH")
        self.assertEqual(get_risk_level(85), "CRITICAL")
        self.assertEqual(get_risk_level(100), "CRITICAL")

    # 2. Risk level out of bounds validation
    def test_risk_level_invalid_scores(self) -> None:
        with self.assertRaises(ValueError):
            get_risk_level(-1)
        with self.assertRaises(ValueError):
            get_risk_level(101)
        with self.assertRaises(ValueError):
            get_risk_level(50.5)  # type: ignore
        with self.assertRaises(ValueError):
            get_risk_level("50")  # type: ignore
        with self.assertRaises(ValueError):
            get_risk_level(True)  # type: ignore

    # 3. AI Threat scoring
    def test_ai_threat_scoring_malicious_high_confidence(self) -> None:
        # Malicious confidence 1.0 -> 25
        score_max = score_ai_threat({"label": "MALICIOUS", "confidence": 1.0})
        self.assertEqual(score_max, 25)

        # Malicious confidence 0.8 -> round(0.8 * 25) = 20
        score_80 = score_ai_threat({"label": "MALICIOUS", "confidence": 0.8})
        self.assertEqual(score_80, 20)

        # Malicious confidence 0.98 -> round(0.98 * 25) = round(24.5) = 24
        score_98 = score_ai_threat({"label": "MALICIOUS", "confidence": 0.98})
        self.assertEqual(score_98, 24)

        # Malicious confidence 0.99 -> round(0.99 * 25) = 25
        score_99 = score_ai_threat({"label": "MALICIOUS", "confidence": 0.99})
        self.assertEqual(score_99, 25)

        # Malicious without confidence default
        score_default = score_ai_threat({"label": "MALICIOUS"})
        self.assertEqual(score_default, 15)

    def test_ai_threat_scoring_benign_high_confidence(self) -> None:
        # Benign with high confidence -> 0
        score_benign = score_ai_threat({"label": "BENIGN", "confidence": 0.99})
        self.assertEqual(score_benign, 0)

        # Clean label -> 0
        score_clean = score_ai_threat({"label": "CLEAN", "confidence": 0.95})
        self.assertEqual(score_clean, 0)

    def test_ai_threat_scoring_suspicious(self) -> None:
        score_suspicious = score_ai_threat({"label": "SUSPICIOUS", "confidence": 0.9})
        self.assertEqual(score_suspicious, 14)

    # 4. Identity scoring
    def test_identity_scoring(self) -> None:
        # Sender/Reply-To mismatch
        score_reply = score_identity({"sender_reply_to_mismatch": True})
        self.assertEqual(score_reply, 8)

        # Sender/Return-Path mismatch
        score_return = score_identity({"sender_return_path_mismatch": True})
        self.assertEqual(score_return, 8)

        # Both mismatches plus spoofing
        score_combo = score_identity({
            "sender_reply_to_mismatch": True,
            "sender_return_path_mismatch": True,
            "domain_spoofing": True,
        })
        # 8 + 8 + 6 = 22, clamped to max 20
        self.assertEqual(score_combo, 20)

        # Clean identity
        self.assertEqual(score_identity({}), 0)

    # 5. Authentication scoring
    def test_authentication_scoring(self) -> None:
        # All pass -> 0
        score_pass = score_authentication({"spf": "PASS", "dkim": "PASS", "dmarc": "PASS"})
        self.assertEqual(score_pass, 0)

        # DMARC fail -> 8
        score_dmarc = score_authentication({"spf": "PASS", "dkim": "PASS", "dmarc": "FAIL"})
        self.assertEqual(score_dmarc, 8)

        # SPF fail -> 4
        score_spf = score_authentication({"spf": "FAIL", "dkim": "PASS", "dmarc": "PASS"})
        self.assertEqual(score_spf, 4)

        # DKIM fail -> 4
        score_dkim = score_authentication({"spf": "PASS", "dkim": "FAIL", "dmarc": "PASS"})
        self.assertEqual(score_dkim, 4)

        # Triple failure: 8 + 4 + 4 = 16, clamped to max 15
        score_all_fail = score_authentication({"spf": "FAIL", "dkim": "FAIL", "dmarc": "FAIL"})
        self.assertEqual(score_all_fail, 15)

    # 6. URL / Domain scoring
    def test_url_domain_scoring(self) -> None:
        # Suspicious domain -> 8
        score_dom = score_url_domain({"suspicious_domain": True})
        self.assertEqual(score_dom, 8)

        # Suspicious URL -> 6
        score_url = score_url_domain({"suspicious_url": True})
        self.assertEqual(score_url, 6)

        # Combo: 8 + 6 + 4 = 18, clamped to 15
        score_combo = score_url_domain({
            "suspicious_domain": True,
            "suspicious_url": True,
            "domain_mismatch": True,
        })
        self.assertEqual(score_combo, 15)

        # Clean
        self.assertEqual(score_url_domain({}), 0)

    # 7. Infrastructure scoring
    def test_infrastructure_scoring(self) -> None:
        # Suspicious IP -> 8
        score_ip = score_infrastructure({"suspicious_ip": True})
        self.assertEqual(score_ip, 8)

        # Suspicious hosting -> 5
        score_host = score_infrastructure({"suspicious_hosting": True})
        self.assertEqual(score_host, 5)

        # Combo: 8 + 5 + 5 = 18, clamped to 15
        score_combo = score_infrastructure({
            "suspicious_ip": True,
            "suspicious_hosting": True,
            "suspicious_asn": True,
        })
        self.assertEqual(score_combo, 15)

        # Clean
        self.assertEqual(score_infrastructure({}), 0)

    # 8. Campaign scoring
    def test_campaign_scoring(self) -> None:
        # Potential campaign -> 10
        score_camp = score_campaign({"potential_campaign": True})
        self.assertEqual(score_camp, 10)

        # Campaign detected -> 10
        score_det = score_campaign({"campaign_detected": True})
        self.assertEqual(score_det, 10)

        # Cluster id present -> 5
        score_cluster = score_campaign({"cluster_id": "camp_abc"})
        self.assertEqual(score_cluster, 5)

        # Multiple targets -> 5
        score_multi = score_campaign({"multiple_targets_detected": True})
        self.assertEqual(score_multi, 5)

        # Clean
        self.assertEqual(score_campaign({}), 0)

    # 9. Invariant: Sum of category breakdown equals total score
    def test_breakdown_sums_to_total(self) -> None:
        evidence = {
            "ml": {"label": "MALICIOUS", "confidence": 0.98},
            "identity": {
                "sender_reply_to_mismatch": True,
                "sender_return_path_mismatch": True,
            },
            "authentication": {
                "spf": "PASS",
                "dkim": "PASS",
                "dmarc": "FAIL",
            },
            "url_domain": {
                "suspicious_domain": True,
            },
            "infrastructure": {
                "suspicious_ip": True,
            },
            "campaign": {
                "potential_campaign": True,
            },
        }
        res = self.engine.calculate_risk(evidence)
        breakdown = res["breakdown"]
        expected_sum = sum(breakdown.values())

        self.assertEqual(res["total_score"], expected_sum)
        self.assertEqual(res["level"], get_risk_level(res["total_score"]))
        # Verify 6 category keys exist
        expected_categories = {
            "ai_threat",
            "identity",
            "authentication",
            "url_domain",
            "infrastructure",
            "campaign",
        }
        self.assertEqual(set(breakdown.keys()), expected_categories)

    # 10. Invariant: Score stays strictly within [0, 100]
    def test_total_score_boundaries(self) -> None:
        # Empty evidence -> 0, LOW
        zero_res = self.engine.calculate_risk({})
        self.assertEqual(zero_res["total_score"], 0)
        self.assertEqual(zero_res["level"], "LOW")
        self.assertEqual(sum(zero_res["breakdown"].values()), 0)

        # All categories maximum possible indicators -> 100, CRITICAL
        max_evidence = {
            "ml": {"label": "MALICIOUS", "confidence": 1.0},
            "identity": {
                "sender_reply_to_mismatch": True,
                "sender_return_path_mismatch": True,
                "domain_spoofing": True,
            },
            "authentication": {"spf": "FAIL", "dkim": "FAIL", "dmarc": "FAIL"},
            "url_domain": {"suspicious_domain": True, "suspicious_url": True, "punycode_or_homograph": True},
            "infrastructure": {"suspicious_ip": True, "suspicious_hosting": True, "suspicious_asn": True},
            "campaign": {"potential_campaign": True, "multiple_targets_detected": True},
        }
        max_res = self.engine.calculate_risk(max_evidence)
        self.assertEqual(max_res["total_score"], 100)
        self.assertEqual(max_res["level"], "CRITICAL")
        self.assertEqual(sum(max_res["breakdown"].values()), 100)
        self.assertEqual(max_res["breakdown"]["ai_threat"], 25)
        self.assertEqual(max_res["breakdown"]["identity"], 20)
        self.assertEqual(max_res["breakdown"]["authentication"], 15)
        self.assertEqual(max_res["breakdown"]["url_domain"], 15)
        self.assertEqual(max_res["breakdown"]["infrastructure"], 15)
        self.assertEqual(max_res["breakdown"]["campaign"], 10)

    # 11. Malformed and None evidence handled safely
    def test_malformed_evidence_safe_handling(self) -> None:
        # None input
        none_res = self.engine.calculate_risk(None)
        self.assertEqual(none_res["total_score"], 0)
        self.assertEqual(none_res["level"], "LOW")

        # Wrong types in values
        bad_evidence = {
            "ml": "not a dict",
            "identity": None,
            "authentication": 12345,
            "url_domain": ["item"],
            "infrastructure": True,
            "campaign": "bad string",
        }
        bad_res = self.engine.calculate_risk(bad_evidence)
        self.assertEqual(bad_res["total_score"], 0)
        self.assertEqual(bad_res["level"], "LOW")

    # 12. RiskService pipeline stage integration
    def test_risk_service_stage_integration(self) -> None:
        service = RiskService(risk_engine=self.engine)
        email = NormalizedEmail(
            provider="gmail",
            provider_message_id="stage-test-id",
            sender="sender@example.com",
            recipient="recipient@example.com",
        )
        context = {
            "ml": {"label": "MALICIOUS", "confidence": 0.8},
            "authentication": {"spf": "PASS", "dkim": "PASS", "dmarc": "FAIL"},
            "campaign": {"potential_campaign": True},
        }
        res = service.analyze(email=email, context=context)
        self.assertEqual(res["status"], "completed")
        self.assertEqual(res["stage"], "risk")
        self.assertIn("total_score", res)
        self.assertIn("level", res)
        self.assertIn("breakdown", res)
        self.assertGreater(res["total_score"], 0)
        self.assertEqual(res["total_score"], sum(res["breakdown"].values()))


if __name__ == "__main__":
    unittest.main()
