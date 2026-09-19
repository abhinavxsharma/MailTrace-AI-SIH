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
            from intelligence.rdap.client import RdapClient
            from intelligence.dns.resolver import DnsIntelligenceResolver

            enricher = EmailIntelligenceEnricher(
                max_domains=3,
                max_ips=3,
                max_urls=3,
                rdap_client=RdapClient(timeout=1.5),
                dns_resolver=DnsIntelligenceResolver(timeout=1.5),
            )
            enriched = enricher.enrich(parsed)

            # Analyze URLs for suspicious signals and domain mismatches
            sender_domain = parsed.from_address.domain.lower() if parsed.from_address and parsed.from_address.domain else ""
            suspicious_keywords = ("login", "verify", "steal", "phish", "account", "banking", "secure", "update", "signin", "auth", "credential", "password", "reset", "invoice")
            
            has_suspicious_url = False
            has_domain_mismatch = False
            has_punycode = False

            for u in parsed.extracted_urls:
                u_str = (u.original_url or "").lower()
                u_host = (u.host or "").strip("[]").lower()
                if any(kw in u_str for kw in suspicious_keywords):
                    has_suspicious_url = True
                if u_host and sender_domain and u_host != sender_domain and not u_host.endswith("." + sender_domain):
                    has_domain_mismatch = True
            any_malicious = any(
                r.get("verdict") in ("MALICIOUS", "SUSPICIOUS") or r.get("score", 0) > 50
                for r in enriched.reputation.values()
            )

            # Extract Observed Source Infrastructure from hops and geoip
            observed_ips = []
            for hop in parsed.received_hops:
                for raw in (hop.from_host, hop.by_host, hop.original_value):
                    if not raw:
                        continue
                    import re
                    found = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", raw)
                    for f in found:
                        if f not in observed_ips:
                            observed_ips.append(f)

            is_suspicious_ip = any(
                enriched.reputation.get(ip, {}).get("verdict") in ("MALICIOUS", "SUSPICIOUS")
                for ip in observed_ips
            )

            geo_data = {}
            primary_source_ip = None
            primary_ptr = None
            primary_org = None
            primary_asn = None
            primary_country = None

            for ip in observed_ips[:5]:
                res = enricher.geoip_resolver.resolve(ip).model_dump()
                # If organization or reverse DNS is missing, attempt quick resolution
                ptr_name = None
                try:
                    import socket
                    socket.setdefaulttimeout(1.0)
                    ptr_name = socket.gethostbyaddr(ip)[0]
                except Exception:
                    pass
                res["reverse_dns"] = ptr_name

                if not res.get("organization") or res.get("status") == "DATABASE_MISSING":
                    try:
                        rdap_res = enricher.rdap_client.lookup_ip(ip)
                        if rdap_res.organization:
                            res["organization"] = rdap_res.organization
                        if rdap_res.asn:
                            res["asn"] = rdap_res.asn
                        if rdap_res.network_cidr:
                            res["network_cidr"] = rdap_res.network_cidr
                        if rdap_res.country:
                            res["country"] = rdap_res.country
                    except Exception:
                        pass

                # Fallbacks for well-known cloud/mail relays if still None
                if not res.get("organization") and ptr_name:
                    if "google.com" in ptr_name:
                        res["organization"] = "Google LLC"
                        res["country"] = res.get("country") or "United States"
                    elif "outlook.com" in ptr_name or "microsoft" in ptr_name:
                        res["organization"] = "Microsoft Corporation"
                        res["country"] = res.get("country") or "United States"

                geo_data[ip] = res
                if not primary_source_ip and not res.get("evidence", {}).get("is_private"):
                    primary_source_ip = ip
                    primary_ptr = ptr_name
                    primary_org = res.get("organization")
                    primary_asn = res.get("asn") or res.get("network_cidr")
                    primary_country = res.get("country")

            return {
                "status": "completed",
                "stage": self.stage_name,
                "domain_reputation": "malicious" if any_malicious else "benign",
                "ip_reputation": "malicious" if is_suspicious_ip else "benign",
                "threat_indicators": [
                    k for k, r in enriched.reputation.items()
                    if r.get("verdict") in ("MALICIOUS", "SUSPICIOUS")
                ],
                "indicators_count": len(enriched.indicators),
                "dns_records_count": len(enriched.dns),
                "rdap_records_count": len(enriched.rdap),
                "primary_source_ip": primary_source_ip or (observed_ips[0] if observed_ips else "UNKNOWN"),
                "primary_ptr": primary_ptr or "No PTR record",
                "primary_organization": primary_org or "Internet Assigned Numbers Authority",
                "primary_asn": primary_asn or "Unavailable",
                "primary_country": primary_country or "Unknown",
                "observed_source_infrastructure": {
                    "ips": observed_ips,
                    "ip_geolocation": geo_data,
                    "primary_ip": primary_source_ip or (observed_ips[0] if observed_ips else "UNKNOWN"),
                    "primary_ptr": primary_ptr,
                    "primary_org": primary_org,
                    "attribution_note": "Approximate IP Geolocation for Observed Source Infrastructure. Early hops are evaluated factually.",
                },
                "url_domain": {
                    "suspicious_domain": any_malicious,
                    "suspicious_url": has_suspicious_url or any_malicious,
                    "domain_mismatch": has_domain_mismatch,
                    "punycode_or_homograph": has_punycode,
                },
                "infrastructure": {
                    "suspicious_ip": is_suspicious_ip,
                    "anomalous_routing": len(parsed.received_hops) > 5,
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

