"""
MAILTRACE AI — Deterministic Campaign Clustering Engine.

Clusters correlated emails into campaign groups using deterministic graph connectivity
over explicit correlation matches. Operates strictly in memory with full provenance.
"""

from __future__ import annotations

from collections import defaultdict
import hashlib
from typing import Any

from graph.campaign.models import CampaignCluster
from graph.correlation.engine import CorrelationEngine
from graph.correlation.models import AnalyzedEmailContext, CorrelationMatch

_REASON_WEIGHTS: dict[str, float] = {
    "shared_url": 0.35,
    "shared_sender": 0.30,
    "shared_reply_to": 0.30,
    "shared_ip": 0.25,
    "shared_dkim_domain": 0.20,
    "shared_domain": 0.20,
    "shared_url_domain": 0.20,
    "shared_subject_pattern": 0.15,
    "shared_return_path": 0.15,
}


class CampaignClusterer:
    """
    Deterministic, rule-based campaign clustering engine.

    Attributes:
        correlation_engine: Engine for computing pairwise matches if not precomputed.
    """

    def __init__(self, correlation_engine: CorrelationEngine | None = None):
        self.correlation_engine = correlation_engine or CorrelationEngine()

    def cluster(
        self,
        contexts: list[AnalyzedEmailContext],
        correlations: list[CorrelationMatch] | None = None,
    ) -> list[CampaignCluster]:
        """
        Group analyzed emails into campaign clusters based on correlation matches.

        Args:
            contexts: List of AnalyzedEmailContext objects.
            correlations: Optional precomputed list of CorrelationMatch objects.

        Returns:
            List of ``CampaignCluster`` objects sorted deterministically.
        """
        if len(contexts) < 2:
            return []

        # 1. Obtain or compute correlations
        if correlations is None:
            matches = self.correlation_engine.correlate_batch(contexts)
        else:
            matches = correlations

        if not matches:
            return []

        # 2. Build adjacency graph of email IDs
        adj: dict[str, set[str]] = defaultdict(set)
        edge_matches: dict[frozenset[str], list[CorrelationMatch]] = defaultdict(list)

        for m in matches:
            id1 = m.email_id_1
            id2 = m.email_id_2
            adj[id1].add(id2)
            adj[id2].add(id1)
            edge_matches[frozenset([id1, id2])].append(m)

        # 3. Find connected components (BFS/DFS)
        visited: set[str] = set()
        components: list[set[str]] = []

        all_nodes = sorted(adj.keys())
        for node in all_nodes:
            if node not in visited:
                comp: set[str] = set()
                queue = [node]
                visited.add(node)
                while queue:
                    curr = queue.pop(0)
                    comp.add(curr)
                    for nbr in sorted(adj[curr]):
                        if nbr not in visited:
                            visited.add(nbr)
                            queue.append(nbr)
                if len(comp) >= 2:
                    components.append(comp)

        # 4. Construct CampaignCluster for each component
        clusters: list[CampaignCluster] = []

        for comp in components:
            member_ids = sorted(comp)

            # Collect matches belonging to this component
            comp_matches: list[CorrelationMatch] = []
            for i in range(len(member_ids)):
                for j in range(i + 1, len(member_ids)):
                    pair_key = frozenset([member_ids[i], member_ids[j]])
                    comp_matches.extend(edge_matches.get(pair_key, []))

            # Deduplicate indicators and reasons
            shared_indicators = sorted({m.shared_indicator for m in comp_matches})
            correlation_reasons = sorted({m.reason for m in comp_matches})

            # Deterministic campaign ID from sorted members and primary indicators
            hash_input = f"{':'.join(member_ids)}|{':'.join(shared_indicators)}|{':'.join(correlation_reasons)}"
            campaign_hash = hashlib.sha256(hash_input.encode("utf-8")).hexdigest()[:12]
            campaign_id = f"camp_{campaign_hash}"

            # Calculate explainable strength (0.0 to 1.0)
            strength = self._calculate_strength(correlation_reasons, shared_indicators)

            evidence = {
                "member_count": len(member_ids),
                "total_correlation_matches": len(comp_matches),
                "reasons": correlation_reasons,
                "shared_indicators": shared_indicators,
                "matches": [
                    {
                        "pair": [m.email_id_1, m.email_id_2],
                        "reason": m.reason,
                        "indicator": m.shared_indicator,
                    }
                    for m in comp_matches
                ],
            }

            clusters.append(
                CampaignCluster(
                    campaign_id=campaign_id,
                    member_email_ids=member_ids,
                    shared_indicators=shared_indicators,
                    correlation_reasons=correlation_reasons,
                    strength=strength,
                    evidence=evidence,
                )
            )

        # Sort clusters deterministically: largest member count first, then campaign_id
        clusters.sort(key=lambda c: (-len(c.member_email_ids), c.campaign_id))
        return clusters

    @staticmethod
    def _calculate_strength(reasons: list[str], indicators: list[str]) -> float:
        """
        Calculate an explainable correlation strength score (0.0 to 1.0).

        Base strength is 0.50. Each distinct reason category contributes according
        to its forensic specificity.
        """
        if not reasons:
            return 0.0

        weight_sum = sum(_REASON_WEIGHTS.get(r, 0.10) for r in reasons)
        # Bounded between 0.40 and 1.00
        raw = 0.40 + (weight_sum * 0.50) + (min(len(indicators), 5) * 0.02)
        return min(1.0, round(raw, 2))
