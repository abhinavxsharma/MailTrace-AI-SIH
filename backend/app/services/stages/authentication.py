"""Email authentication stage verifying SPF, DKIM, and DMARC."""

from typing import Any, Dict
from backend.app.core.logging import logger
from backend.app.schemas.analysis import NormalizedEmail
from backend.app.services.stages.base import BaseAnalysisStage


class AuthenticationService(BaseAnalysisStage):
    """Email authentication service verifying SPF, DKIM, and DMARC alignment."""

    stage_name: str = "authentication"

    def analyze(self, email: NormalizedEmail, context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute authentication analysis on ingested email."""
        try:
            from forensics.email_parser.parser import parse_email
            from forensics.authentication.verifier import verify_authentication

            parsed = parse_email(email)
            auth_res = verify_authentication(parsed)

            spf_status = auth_res.spf.status.value if hasattr(auth_res.spf.status, "value") else str(auth_res.spf.status)
            dkim_status = auth_res.dkim.status.value if hasattr(auth_res.dkim.status, "value") else str(auth_res.dkim.status)
            dmarc_status = auth_res.dmarc.status.value if hasattr(auth_res.dmarc.status, "value") else str(auth_res.dmarc.status)
            is_authenticated = dmarc_status.lower() == "pass" or (spf_status.lower() == "pass" and dkim_status.lower() == "pass")

            return {
                "status": "completed",
                "stage": self.stage_name,
                "spf": spf_status,
                "dkim": dkim_status,
                "dmarc": dmarc_status,
                "authenticated": is_authenticated,
                "alignment": {
                    "spf_aligned": auth_res.alignment.spf_aligned if hasattr(auth_res, "alignment") else False,
                    "dkim_aligned": auth_res.alignment.dkim_aligned if hasattr(auth_res, "alignment") else False,
                },
                "discrepancies": [d.message for d in getattr(auth_res, "discrepancies", [])],
            }
        except Exception as exc:
            logger.warning("Authentication analysis stage error: %s", str(exc))
            return {
                "status": "not_implemented",
                "stage": self.stage_name,
                "message": f"Authentication analysis fallback: {exc}",
                "spf": "none",
                "dkim": "none",
                "dmarc": "none",
                "authenticated": False,
            }

