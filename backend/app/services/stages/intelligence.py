"""Threat intelligence enrichment stage."""

from typing import Any, Dict
from backend.app.core.logging import logger
from backend.app.schemas.analysis import NormalizedEmail
from backend.app.services.stages.base import BaseAnalysisStage


class IntelligenceService(BaseAnalysisStage):
    """Threat intelligence service providing DNS, RDAP, GeoIP, and reputation feeds."""

    stage_name: str = "intelligence"

    def analyze(self, email: NormalizedEmail, context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute threat intelligence enrichment on ingested email."""
        try:
            from forensics.email_parser.parser import parse_email
            from intelligence.enricher import EmailIntelligenceEnricher

            parsed = parse_email(email)
            enricher = EmailIntelligenceEnricher(max_domains=5, max_ips=5, max_urls=5)
            enriched = enricher.enrich(parsed)

            # Summarize threat indicators
            any_malicious = any(
                r.get("verdict") in ("MALICIOUS", "SUSPICIOUS") or r.get("score", 0) > 50
                for r in enriched.reputation.values()
            )

            return {
                "status": "completed",
                "stage": self.stage_name,
                "domain_reputation": "malicious" if any_malicious else "benign",
                "ip_reputation": "benign",
                "threat_indicators": [
                    k for k, r in enriched.reputation.items()
                    if r.get("verdict") in ("MALICIOUS", "SUSPICIOUS")
                ],
                "indicators_count": len(enriched.indicators),
                "dns_records_count": len(enriched.dns),
                "rdap_records_count": len(enriched.rdap),
                "url_domain": {
                    "suspicious_domain": any_malicious,
                    "suspicious_url": False,
                },
                "infrastructure": {
                    "anomalous_routing": False,
                },
            }
        except Exception as exc:
            logger.warning("Intelligence analysis stage error: %s", str(exc))
            return {
                "status": "not_implemented",
                "stage": self.stage_name,
                "message": f"Threat intelligence fallback: {exc}",
                "domain_reputation": "unknown",
                "ip_reputation": "unknown",
                "threat_indicators": [],
                "url_domain": {},
                "infrastructure": {},
            }

