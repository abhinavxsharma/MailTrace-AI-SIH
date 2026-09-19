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

            return {
                "status": "completed",
                "stage": self.stage_name,
                "extracted_urls": extracted_urls,
                "attachments_count": len(parsed.attachments),
                "headers_count": len(parsed.headers),
                "body_length": len(parsed.body_text or ""),
                "received_hops_count": len(parsed.received_hops),
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

