"""Forensics analysis stage extracting email artifacts, headers, and body structures."""

from typing import Any, Dict
from backend.app.core.logging import logger
from backend.app.schemas.analysis import NormalizedEmail
from backend.app.services.stages.base import BaseAnalysisStage


class ForensicsService(BaseAnalysisStage):
    """Forensic investigation service extracting email artifacts, headers, and body structures."""

    stage_name: str = "forensics"

    def analyze(self, email: NormalizedEmail, context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute forensic analysis on ingested email."""
        try:
            from forensics.email_parser.parser import parse_email
            from forensics.headers.forensics import analyze_headers

            parsed = parse_email(email)
            header_forensics = analyze_headers(parsed)

            extracted_urls = [u.original_url for u in parsed.extracted_urls]
            finding_codes = {f.code for f in header_forensics.findings}

            # Extract identity indicators consumed by the deterministic risk engine
            sender_reply_to_mismatch = "SENDER_REPLY_TO_MISMATCH" in finding_codes
            sender_return_path_mismatch = "SENDER_RETURN_PATH_MISMATCH" in finding_codes
            domain_spoofing = "DOMAIN_SPOOFING" in finding_codes or "DISPLAY_NAME_SPOOFING" in finding_codes
            display_name_spoofing = "DISPLAY_NAME_SPOOFING" in finding_codes

            body_snippet = (parsed.body_text or "")[:500]
            header_items = [{"name": h.name, "value": h.normalized_value or h.original_value} for h in parsed.headers[:50]]
            hops_items = [
                {
                    "hop_index": idx,
                    "by_host": h.by_host,
                    "from_host": h.from_host,
                    "timestamp": str(h.timestamp) if h.timestamp else None,
                    "raw": h.original_value,
                }
                for idx, h in enumerate(parsed.received_hops[:10])
            ]

            return {
                "status": "completed",
                "stage": self.stage_name,
                "extracted_urls": extracted_urls,
                "url_hosts": list({u.host.strip("[]").lower() for u in parsed.extracted_urls if u.host}),
                "attachments_count": len(parsed.attachments),
                "headers_count": len(parsed.headers),
                "body_length": len(parsed.body_text or ""),
                "body_snippet": body_snippet,
                "received_hops_count": len(parsed.received_hops),
                "received_hops": hops_items,
                "headers": header_items,
                "sender_domain": parsed.from_address.domain if parsed.from_address else None,
                "return_path_domain": parsed.return_path.domain if parsed.return_path else None,
                "reply_to_addresses": [r.email for r in parsed.reply_to_addresses if r.email],
                "findings": [
                    {
                        "code": f.code,
                        "category": f.category,
                        "severity": f.severity,
                        "description": f.description,
                    }
                    for f in header_forensics.findings
                ],
                "identity": {
                    "sender_reply_to_mismatch": sender_reply_to_mismatch,
                    "sender_return_path_mismatch": sender_return_path_mismatch,
                    "domain_spoofing": domain_spoofing,
                    "display_name_spoofing": display_name_spoofing,
                    "inconsistent_headers": len(header_forensics.findings) > 0,
                },
            }
        except Exception as exc:
            logger.warning("Forensics analysis stage error: %s", str(exc))
            return {
                "status": "not_implemented",
                "stage": self.stage_name,
                "message": f"Forensics analysis fallback: {exc}",
                "extracted_urls": [],
                "attachments_count": 0,
                "headers_count": len(email.headers),
                "body_length": len(email.body),
                "findings": [],
                "identity": {},
            }

