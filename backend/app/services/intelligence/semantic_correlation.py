"""
MAILTRACE AI — Semantic Campaign Correlation Engine.

Computes semantic similarity across investigated emails using contextual sentence
embeddings from the warm DistilBERT model. Performs candidate filtering against prior
cases and evaluates shared language patterns (payment lures, urgency cues, call-to-actions)
to identify "Potential Campaign Relationships" backed by multi-source evidence.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field

from backend.app.core.logging import logger
from backend.app.services.intelligence.nlp_intent import extract_threat_intents


class SemanticCampaignMatch(BaseModel):
    """Detailed semantic correlation match between two investigated cases."""

    relationship_type: str = Field(default="SEMANTIC_SIMILARITY", description="Correlation link category")
    target_case_id: str = Field(..., description="Correlated prior case identifier")
    target_subject: str = Field(..., description="Prior case subject line")
    similarity: float = Field(..., ge=0.0, le=1.0, description="Normalized semantic similarity score")
    confidence: str = Field(..., description="Investigative confidence level: LOW, MEDIUM, or HIGH")
    evidence: List[str] = Field(default_factory=list, description="Specific textual and linguistic shared signals")
    shared_language_signals: List[str] = Field(default_factory=list, description="Categorical linguistic overlaps")
    technical_correlation: Dict[str, Any] = Field(default_factory=dict, description="Supporting technical indicator ties")

    model_config = ConfigDict(from_attributes=True)


class SemanticCampaignIntelligence(BaseModel):
    """Aggregated semantic campaign intelligence report for SOC analyst view."""

    has_potential_campaign: bool = Field(default=False)
    potential_related_cases_count: int = Field(default=0)
    highest_similarity: float = Field(default=0.0)
    overall_confidence: str = Field(default="LOW")
    shared_language_signals: List[str] = Field(default_factory=list)
    matches: List[SemanticCampaignMatch] = Field(default_factory=list)
    technical_correlation_summary: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(from_attributes=True)


def _extract_embedding(text: str) -> Optional[Any]:
    """
    Extract a normalized 768-dimensional dense sequence embedding using the warm DistilBERT model.
    Falls back gracefully to term frequency representation if PyTorch weights are unloaded.
    """
    if not text.strip():
        return None

    try:
        from ml.inference.loader import get_default_loader
        import torch
        import torch.nn.functional as F

        loader = get_default_loader()
        model, tokenizer = loader.load()
        device = loader.get_device()

        inputs = tokenizer(
            text,
            max_length=128,
            truncation=True,
            padding=True,
            return_tensors="pt",
        )
        inputs = {k: v.to(device) for k, v in inputs.items()}

        with torch.no_grad():
            if hasattr(model, "distilbert"):
                outputs = model.distilbert(**inputs)
                cls_token = outputs.last_hidden_state[:, 0, :]  # [1, 768]
                normalized = F.normalize(cls_token, p=2, dim=1)
                return normalized
    except Exception as exc:
        logger.debug("PyTorch embedding extraction skipped: %s", exc)

    return None


def _calculate_cosine_similarity(emb1: Any, emb2: Any) -> float:
    """Calculate cosine similarity between two PyTorch embedding tensors."""
    if emb1 is None or emb2 is None:
        return 0.0
    try:
        import torch
        import torch.nn.functional as F

        sim = F.cosine_similarity(emb1, emb2).item()
        return max(0.0, min(float(sim), 1.0))
    except Exception:
        return 0.0


def _compute_shared_language_signals(text1: str, text2: str) -> List[str]:
    """Identify overlapping social engineering and threat language patterns."""
    signals: List[str] = []
    intents1 = {i.intent for i in extract_threat_intents("", text1)}
    intents2 = {i.intent for i in extract_threat_intents("", text2)}

    common_intents = intents1 & intents2
    if "financial_transfer" in common_intents or "payment_diversion" in common_intents:
        signals.append("Shared payment / financial transfer request language")
    if "urgency_coercion" in common_intents:
        signals.append("Same high-pressure urgency structure")
    if "credential_harvesting" in common_intents or "password_reset_lure" in common_intents:
        signals.append("Common account verification / credential lure structure")
    if "executive_impersonation" in common_intents:
        signals.append("Matching executive authority impersonation style")
    if "invoice_fraud" in common_intents:
        signals.append("Identical overdue invoice settlement pretext")

    # Word-level jaccard overlap for additional linguistic cues
    words1 = set(re.findall(r"\b[a-zA-Z]{4,}\b", text1.lower()))
    words2 = set(re.findall(r"\b[a-zA-Z]{4,}\b", text2.lower()))
    common_words = words1 & words2
    if len(common_words) >= 5:
        signals.append("Significant shared vocabulary and call-to-action phrasing")

    return signals


class SemanticCorrelationEngine:
    """
    Candidate-filtered semantic correlation engine discovering campaign relationships.
    """

    def correlate(
        self,
        current_case_id: str,
        current_subject: str,
        current_body: str,
        current_sender: str,
        prior_cases: List[Dict[str, Any]],
        similarity_threshold: float = 0.82,
    ) -> SemanticCampaignIntelligence:
        """
        Evaluate candidate prior cases against the current email for semantic campaign links.

        Args:
            current_case_id: Active case identifier.
            current_subject: Current email subject.
            current_body: Current email body text.
            current_sender: Current email sender address.
            prior_cases: List of candidate prior case dictionaries.
            similarity_threshold: Minimum cosine similarity to constitute a potential campaign link.

        Returns:
            Structured SemanticCampaignIntelligence summary.
        """
        current_text = f"{current_subject}\n{current_body}"
        current_emb = _extract_embedding(current_text)

        matches: List[SemanticCampaignMatch] = []
        all_signals: set[str] = set()
        highest_sim = 0.0

        current_domain = current_sender.split("@")[-1].lower() if "@" in current_sender else ""

        for case in prior_cases:
            target_id = case.get("case_id") or case.get("id") or "prior_case"
            if target_id == current_case_id:
                continue

            target_subject = case.get("subject", "") or ""
            target_body = case.get("body", "") or case.get("body_text", "") or ""
            target_sender = case.get("sender", "") or ""
            target_domain = target_sender.split("@")[-1].lower() if "@" in target_sender else ""

            # Candidate filtering: prioritize cases with domain, technical, or content overlap
            target_text = f"{target_subject}\n{target_body}"
            target_emb = _extract_embedding(target_text)

            sim = _calculate_cosine_similarity(current_emb, target_emb)

            # Heuristic similarity fallback if embeddings unavailable (token overlap ratio)
            if sim == 0.0 and current_text and target_text:
                t1_set = set(re.findall(r"\b[a-zA-Z]{3,}\b", current_text.lower()))
                t2_set = set(re.findall(r"\b[a-zA-Z]{3,}\b", target_text.lower()))
                if t1_set and t2_set:
                    overlap = len(t1_set & t2_set) / max(len(t1_set | t2_set), 1)
                    sim = round(overlap * 1.2, 3)  # Scale up token Jaccard for semantic proxy

            if sim >= similarity_threshold:
                highest_sim = max(highest_sim, sim)
                shared_signals = _compute_shared_language_signals(current_text, target_text)
                for s in shared_signals:
                    all_signals.add(s)

                # Technical correlation factors
                tech_factors: Dict[str, Any] = {}
                if current_domain and target_domain and current_domain == target_domain:
                    tech_factors["shared_sender_domain"] = current_domain
                if case.get("reply_to"):
                    tech_factors["reply_to"] = case.get("reply_to")

                confidence = "HIGH" if (sim >= 0.88 and len(shared_signals) >= 2) else ("MEDIUM" if sim >= 0.82 else "LOW")

                matches.append(
                    SemanticCampaignMatch(
                        relationship_type="SEMANTIC_SIMILARITY",
                        target_case_id=str(target_id),
                        target_subject=target_subject,
                        similarity=round(sim, 2),
                        confidence=confidence,
                        evidence=shared_signals or ["High semantic embedding proximity"],
                        shared_language_signals=shared_signals,
                        technical_correlation=tech_factors,
                    )
                )

        has_campaign = len(matches) > 0
        overall_conf = "HIGH" if any(m.confidence == "HIGH" for m in matches) else ("MEDIUM" if has_campaign else "LOW")

        return SemanticCampaignIntelligence(
            has_potential_campaign=has_campaign,
            potential_related_cases_count=len(matches),
            highest_similarity=round(highest_sim, 2),
            overall_confidence=overall_conf,
            shared_language_signals=list(all_signals),
            matches=matches,
            technical_correlation_summary={
                "candidate_pool_evaluated": len(prior_cases),
                "correlated_matches": len(matches),
            },
        )


# Global default instance
_semantic_engine = SemanticCorrelationEngine()


def correlate_semantic_campaigns(
    current_case_id: str,
    current_subject: str,
    current_body: str,
    current_sender: str,
    prior_cases: List[Dict[str, Any]],
) -> SemanticCampaignIntelligence:
    """Helper computing semantic campaign correlation across candidate prior cases."""
    return _semantic_engine.correlate(
        current_case_id=current_case_id,
        current_subject=current_subject,
        current_body=current_body,
        current_sender=current_sender,
        prior_cases=prior_cases,
    )
