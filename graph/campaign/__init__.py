"""
MAILTRACE AI — Campaign Intelligence Package.

Provides deterministic campaign clustering models and grouping algorithms.
"""

from __future__ import annotations

from graph.campaign.clustering import CampaignClusterer
from graph.campaign.models import CampaignCluster

__all__ = [
    "CampaignCluster",
    "CampaignClusterer",
]
