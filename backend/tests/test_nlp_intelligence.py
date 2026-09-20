"""
MAILTRACE AI — Tests for NLP Threat Intent, Entity Extraction, and Semantic Correlation.
"""

from __future__ import annotations

import pytest
from backend.app.schemas.analysis import NormalizedEmail
from backend.app.services.intelligence.nlp_entities import extract_entities
from backend.app.services.intelligence.nlp_intent import extract_threat_intents
from backend.app.services.intelligence.semantic_correlation import (
    correlate_semantic_campaigns,
    SemanticCampaignIntelligence,
)
from backend.app.services.pre_open_scan import scan_email_pre_open


class TestNlpThreatIntent:
    """Test structured threat intent taxonomy and evidence extraction."""

    def test_financial_and_payment_diversion_intent(self):
        subject = "Urgent: Revised Banking Wire Details"
        body = "Please update our banking details and remit to the new account $48,500 before close of business."
        intents = extract_threat_intents(subject=subject, body=body)

        intent_names = {i.intent for i in intents}
        assert "payment_diversion" in intent_names
        assert "financial_transfer" in intent_names

        payment_intent = next(i for i in intents if i.intent == "payment_diversion")
        assert payment_intent.confidence >= 0.90
        assert "divert funds or update bank account" in payment_intent.explanation
        assert "Matched trigger:" in payment_intent.evidence

    def test_credential_harvesting_and_account_takeover(self):
        subject = "Security Alert: Unauthorized sign-in attempt detected"
        body = "Your account will be suspended. Verify your account and confirm your credentials immediately."
        intents = extract_threat_intents(subject=subject, body=body)

        intent_names = {i.intent for i in intents}
        assert "credential_harvesting" in intent_names
        assert "account_takeover" in intent_names
        assert "urgency_coercion" in intent_names

    def test_executive_impersonation_and_urgency(self):
        subject = "Confidential Request"
        body = "Sent from my iPhone. I am currently in a meeting, do not call me. Need you to handle this urgently."
        intents = extract_threat_intents(subject=subject, body=body, sender_display_name="CEO Office")

        intent_names = {i.intent for i in intents}
        assert "executive_impersonation" in intent_names
        assert "urgency_coercion" in intent_names

    def test_benign_routine_email_has_no_threat_intents(self):
        subject = "Sprint Planning Sync Notes"
        body = "Hi team, please find the agenda for tomorrow's standup. We will review tickets on GitHub."
        intents = extract_threat_intents(subject=subject, body=body)
        assert len(intents) == 0


class TestNlpEntityExtraction:
    """Test 16 structured entity extraction categories without hallucination."""

    def test_extraction_of_financial_and_urgency_entities(self):
        subject = "Urgent Payment Notice"
        body = (
            "Please wire transfer $18,500 USD to routing number 021000021 before 4 PM.\n"
            "If questions arise, reach our fraud desk at +1 (800) 555-0199 or contact support@acme-corp.com.\n"
            "Regards,\nDavid Miller"
        )
        entities = extract_entities(
            subject=subject,
            body=body,
            sender_name="David Miller",
            sender_email="finance@vendor.com",
        )

        types_found = {e.type for e in entities}
        assert "AMOUNT" in types_found
        assert "CURRENCY" in types_found
        assert "DEADLINE" in types_found
        assert "ACCOUNT_IDENTIFIER" in types_found
        assert "PAYMENT_INSTRUCTION" in types_found
        assert "PHONE" in types_found
        assert "EMAIL" in types_found
        assert "PERSON" in types_found

        amt = next(e for e in entities if e.type == "AMOUNT")
        assert amt.normalized_value == "18500"

        curr = next(e for e in entities if e.type == "CURRENCY")
        assert curr.normalized_value == "USD"

    def test_crypto_wallet_and_platform_extraction(self):
        subject = "Bitcoin payment requirement"
        body = (
            "Send 0.5 BTC to bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq before Friday.\n"
            "Alternatively remit via Ethereum address 0x71C7656EC7ab88b098defB751B7401B5f6d8976F.\n"
            "Document hosted on Microsoft 365."
        )
        entities = extract_entities(subject=subject, body=body)
        types_found = {e.type for e in entities}
        assert "CRYPTO_WALLET" in types_found
        assert "SERVICE_PLATFORM" in types_found

    def test_clean_text_produces_no_hallucinations(self):
        subject = "Team lunch tomorrow"
        body = "Let's meet at the cafeteria at noon."
        entities = extract_entities(subject=subject, body=body)
        types_found = {e.type for e in entities}
        assert "AMOUNT" not in types_found
        assert "CRYPTO_WALLET" not in types_found
        assert "ACCOUNT_IDENTIFIER" not in types_found


class TestSemanticCampaignCorrelation:
    """Test contextual similarity, candidate filtering, and potential campaign relationships."""

    def test_high_similarity_campaign_correlation(self):
        current_case_id = "CASE-2026-001"
        current_subject = "Urgent Wire Transfer Request for Vendor Settlement"
        current_body = "Please process an immediate bank wire transfer of $24,000 to the updated account before close of business."
        current_sender = "cfo@partner-firm.com"

        prior_cases = [
            {
                "case_id": "CASE-2026-002",
                "subject": "Urgent Wire Transfer Payment for Outstanding Invoice",
                "body": "Please remit an immediate bank wire transfer of $19,500 to the new banking details before close of business.",
                "sender": "accounts@partner-firm.com",
            },
            {
                "case_id": "CASE-2026-003",
                "subject": "Weekly Newsletter Digest",
                "body": "Here are the top engineering articles for this week.",
                "sender": "newsletter@tech-news.org",
            },
        ]

        result: SemanticCampaignIntelligence = correlate_semantic_campaigns(
            current_case_id=current_case_id,
            current_subject=current_subject,
            current_body=current_body,
            current_sender=current_sender,
            prior_cases=prior_cases,
        )

        assert result.has_potential_campaign is True
        assert result.potential_related_cases_count >= 1
        assert result.highest_similarity >= 0.82
        assert "Shared payment / financial transfer request language" in result.shared_language_signals

        match = result.matches[0]
        assert match.relationship_type == "SEMANTIC_SIMILARITY"
        assert match.target_case_id == "CASE-2026-002"
        assert match.confidence in ("MEDIUM", "HIGH")

    def test_dissimilar_cases_do_not_form_campaign(self):
        current_case_id = "CASE-100"
        current_subject = "Quarterly Sales All Hands Meeting"
        current_body = "Please join the Zoom call tomorrow at 10 AM to discuss sales goals."
        current_sender = "sales@company.com"

        prior_cases = [
            {
                "case_id": "CASE-101",
                "subject": "Urgent Wire Transfer: Critical Settlement",
                "body": "Send wire transfer of $95,000 immediately to account 12345.",
                "sender": "fraud@hacker-net.com",
            }
        ]

        result = correlate_semantic_campaigns(
            current_case_id=current_case_id,
            current_subject=current_subject,
            current_body=current_body,
            current_sender=current_sender,
            prior_cases=prior_cases,
        )

        assert result.has_potential_campaign is False
        assert result.potential_related_cases_count == 0


class TestPreOpenScanNlpIntegration:
    """Test that pre_open_scan cleanly incorporates NLP Threat Intent and Entity Extraction."""

    def test_pre_open_scan_populates_nlp_intents_and_entities(self):
        email = NormalizedEmail(
            provider="gmail",
            provider_message_id="msg_nlp_test_123",
            sender="CEO <ceo@executive-spoofed.org>",
            recipient="accountspayable@mycompany.com",
            subject="Urgent: Wire Transfer of $32,000 Before 4 PM",
            body="I am currently in a meeting. Update our banking details and remit payment before 4 PM.",
            headers=[
                {"name": "From", "value": "CEO <ceo@executive-spoofed.org>"},
                {"name": "Reply-To", "value": "attacker-drop@external-mail.net"},
                {"name": "Authentication-Results", "value": "mx.google.com; spf=fail; dkim=none; dmarc=fail"},
            ],
        )

        response = scan_email_pre_open(email)
        assert len(response.nlp_intents) > 0
        intent_types = {i.intent for i in response.nlp_intents}
        assert "financial_transfer" in intent_types or "payment_diversion" in intent_types
        assert "urgency_coercion" in intent_types or "executive_impersonation" in intent_types

        # Verify explainable user-readable reasons
        assert any("financial" in r.lower() or "divert" in r.lower() for r in response.reasons)
        assert any("urgency" in r.lower() or "deadline" in r.lower() or "time" in r.lower() for r in response.reasons)

        # Verify extracted entities
        assert len(response.extracted_entities) > 0
        entity_types = {e.type for e in response.extracted_entities}
        assert "AMOUNT" in entity_types
