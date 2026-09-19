"""Unit tests for ML DistilBERT model, AI stages, and demo cases."""

import unittest
from backend.app.db.database import init_db
from backend.app.db.session import SessionLocal
from backend.app.models.enums import CaseStatus
from backend.app.services.demo_cases import (
    get_demo_case_1_legitimate,
    get_demo_case_2_bec,
    get_demo_case_3_campaign_variant,
    seed_demo_cases,
)
from ml.inference.classifier import classify_email


class MlAndAiTestCase(unittest.TestCase):
    """Test suite validating real ML inference, threat classification, and AI correlation."""

    @classmethod
    def setUpClass(cls) -> None:
        init_db()

    def test_real_ml_inference_malicious(self) -> None:
        """Verify real DistilBERT model classifies malicious lure with high confidence."""
        email = {
            "subject": "URGENT: Your Account Has Been Suspended",
            "body": "Please click http://phishing-login-steal.com/verify to restore your account.",
        }
        res = classify_email(email)
        self.assertEqual(res.label, "MALICIOUS")
        self.assertGreaterEqual(res.confidence, 0.99)
        self.assertIn("MALICIOUS", res.probabilities)
        self.assertIn("BENIGN", res.probabilities)
        self.assertGreater(res.probabilities["MALICIOUS"], res.probabilities["BENIGN"])
        self.assertEqual(res.model_version, "dataset3_v1.0.0")

    def test_real_ml_inference_benign(self) -> None:
        """Verify real DistilBERT model classifies normal business communication as benign."""
        email = {
            "subject": "Monthly expense report — September",
            "body": (
                "Hello team, the September monthly expense report is attached for your review. "
                "Please use the normal internal finance portal if you need to submit corrections. "
                "Regards, Finance Office."
            ),
        }
        res = classify_email(email)
        self.assertEqual(res.label, "BENIGN")
        self.assertGreaterEqual(res.confidence, 0.99)
        self.assertGreater(res.probabilities["BENIGN"], res.probabilities["MALICIOUS"])
        self.assertEqual(res.model_version, "dataset3_v1.0.0")

    def test_seed_demo_cases_pipeline(self) -> None:
        """Verify seeding the 3 controlled demo cases runs all stages and links campaigns."""
        db = SessionLocal()
        try:
            results = seed_demo_cases(db=db)
            self.assertEqual(len(results), 3)

            # Case 1: Legitimate
            c1 = results[0]
            self.assertEqual(c1["status"], CaseStatus.ANALYZED.value)
            self.assertEqual(c1["classification"], "BENIGN")
            self.assertLessEqual(c1["risk_score"], 39)

            # Case 2: BEC Fraud
            c2 = results[1]
            self.assertEqual(c2["status"], CaseStatus.ANALYZED.value)
            self.assertEqual(c2["classification"], "MALICIOUS")
            self.assertGreaterEqual(c2["risk_score"], 25)

            # Case 3: Campaign Variant
            c3 = results[2]
            self.assertEqual(c3["status"], CaseStatus.ANALYZED.value)
            self.assertEqual(c3["classification"], "MALICIOUS")
            self.assertTrue(c3["campaign_detected"])
            self.assertIsNotNone(c3["cluster_id"])
        finally:
            db.close()


if __name__ == "__main__":
    unittest.main()
