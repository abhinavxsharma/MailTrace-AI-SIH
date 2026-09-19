"""Analysis pipeline orchestrating multi-stage threat detection workflows."""

from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple
from sqlalchemy.orm import Session

from backend.app.core.logging import logger
from backend.app.models.analysis import Analysis
from backend.app.models.audit import AuditEvent
from backend.app.models.case import Case, generate_case_id
from backend.app.models.enums import CaseStatus, Classification
from backend.app.schemas.analysis import NormalizedEmail
from backend.app.services.case_service import get_case_by_provider_message
from backend.app.services.stages.authentication import AuthenticationService
from backend.app.services.stages.base import BaseAnalysisStage
from backend.app.services.stages.correlation import CorrelationService
from backend.app.services.stages.forensics import ForensicsService
from backend.app.services.stages.intelligence import IntelligenceService
from backend.app.services.stages.ml import MLService
from backend.app.services.stages.risk import RiskService


class AnalysisPipeline:
    """Orchestrator for email security analysis stages.

    Executes forensic, authentication, ML detection, threat intelligence,
    correlation, and risk scoring stages against a normalized email in memory.
    """

    def __init__(
        self,
        forensics: Optional[BaseAnalysisStage] = None,
        authentication: Optional[BaseAnalysisStage] = None,
        ml: Optional[BaseAnalysisStage] = None,
        intelligence: Optional[BaseAnalysisStage] = None,
        correlation: Optional[BaseAnalysisStage] = None,
        risk: Optional[BaseAnalysisStage] = None,
    ) -> None:
        """Initialize the pipeline with injectable stage dependencies."""
        self.forensics = forensics or ForensicsService()
        self.authentication = authentication or AuthenticationService()
        self.ml = ml or MLService()
        self.intelligence = intelligence or IntelligenceService()
        self.correlation = correlation or CorrelationService()
        self.risk = risk or RiskService()

    def run(self, db: Session, email: NormalizedEmail) -> Tuple[Case, Dict[str, Any]]:
        """Run the end-to-end analysis pipeline against an ingested email.

        Args:
            db: Active database session.
            email: In-memory normalized email metadata and content.

        Returns:
            Tuple of the managed Case record and dictionary of stage results.
        """
        logger.info(
            "Starting analysis pipeline for message '%s' from provider '%s'",
            email.provider_message_id,
            email.provider,
        )

        try:
            # 1. Find existing case or create a new one
            case = get_case_by_provider_message(
                db=db,
                provider=email.provider,
                provider_message_id=email.provider_message_id,
            )

            if not case:
                case = Case(
                    case_id=generate_case_id(),
                    mailbox_id=email.mailbox_id,
                    provider=email.provider,
                    provider_message_id=email.provider_message_id,
                    thread_id=email.thread_id,
                    sender=email.sender,
                    recipient=email.recipient,
                    subject=email.subject,
                    received_at=email.received_at or datetime.now(timezone.utc),
                    status=CaseStatus.NEW.value,
                    classification=Classification.PENDING.value,
                )
                db.add(case)
                db.flush()

                db.add(
                    AuditEvent(
                        case_id=case.id,
                        event_type="CASE_CREATED",
                        message=(
                            f"Case {case.case_id} created for message '{case.provider_message_id}' "
                            f"via {case.provider}."
                        ),
                    )
                )
                logger.info("Created new case %s for message %s", case.case_id, case.provider_message_id)
            else:
                logger.info("Reusing existing case %s for message %s", case.case_id, case.provider_message_id)

            # 2. Transition case to PROCESSING
            case.status = CaseStatus.PROCESSING.value
            db.add(
                AuditEvent(
                    case_id=case.id,
                    event_type="STATUS_UPDATED",
                    message=f"Case status transitioned to {CaseStatus.PROCESSING.value} for analysis execution.",
                )
            )
            db.flush()

            # 3. Execute analysis stages sequentially
            stages = [
                ("forensics", self.forensics),
                ("authentication", self.authentication),
                ("ml", self.ml),
                ("intelligence", self.intelligence),
                ("correlation", self.correlation),
                ("risk", self.risk),
            ]

            stage_results: Dict[str, Any] = {}
            context: Dict[str, Any] = {
                "case_id": case.case_id,
                "case_db_id": case.id,
                "provider": email.provider,
                "received_at": str(case.received_at),
                "db": db,
            }

            for stage_name, stage_instance in stages:
                try:
                    result = stage_instance.analyze(email=email, context=context)
                    stage_results[stage_name] = result
                    context[stage_name] = result
                except Exception as e:
                    logger.error(
                        "Analysis stage '%s' failed for case %s: %s",
                        stage_name,
                        case.case_id,
                        str(e),
                        exc_info=True,
                    )
                    stage_results[stage_name] = {
                        "status": "error",
                        "error": str(e),
                    }
                    db.add(
                        AuditEvent(
                            case_id=case.id,
                            event_type=f"STAGE_ERROR_{stage_name.upper()}",
                            message=f"Stage '{stage_name}' encountered an error: {str(e)}",
                        )
                    )

            # 4. Propagate ML stage findings into Case record
            ml_res = stage_results.get("ml", {})
            if isinstance(ml_res, dict) and ml_res.get("status") == "completed":
                raw_label = ml_res.get("label") or ml_res.get("prediction")
                if raw_label:
                    raw_upper = str(raw_label).upper().strip()
                    if raw_upper in Classification.__members__:
                        case.classification = Classification[raw_upper].value
                    elif "MAL" in raw_upper:
                        case.classification = Classification.MALICIOUS.value
                    elif "BEN" in raw_upper:
                        case.classification = Classification.BENIGN.value
                    elif "SUSP" in raw_upper:
                        case.classification = Classification.SUSPICIOUS.value

                raw_conf = ml_res.get("confidence")
                if isinstance(raw_conf, (int, float)) and not isinstance(raw_conf, bool):
                    case.ai_confidence = float(raw_conf)

            # 5. Propagate Risk score into Case record
            if "risk" in stage_results and isinstance(stage_results["risk"], dict):
                calculated_score = stage_results["risk"].get("total_score")
                if calculated_score is not None and isinstance(calculated_score, int):
                    case.risk_score = max(0, min(calculated_score, 100))

            # 6. Mark case status as ANALYZED upon pipeline completion
            case.status = CaseStatus.ANALYZED.value

            # 7. Persist Analysis record with structured stage results
            analysis = Analysis(
                case_id=case.id,
                classification=case.classification,
                ai_confidence=case.ai_confidence,
                risk_score=case.risk_score,
                forensics=stage_results.get("forensics", {}),
                authentication=stage_results.get("authentication", {}),
                ml=stage_results.get("ml", {}),
                intelligence=stage_results.get("intelligence", {}),
                correlation=stage_results.get("correlation", {}),
                risk=stage_results.get("risk", {}),
            )
            db.add(analysis)

            # 8. Record pipeline completion audit event
            db.add(
                AuditEvent(
                    case_id=case.id,
                    event_type="CASE_ANALYZED",
                    message=(
                        f"Analysis pipeline completed {len(stages)} stages for case {case.case_id}. "
                        f"Status: {case.status}, Classification: {case.classification}, "
                        f"AI Confidence: {case.ai_confidence}, Risk Score: {case.risk_score}."
                    ),
                )
            )

            db.commit()
            db.refresh(case)

            logger.info("Pipeline execution completed for case %s", case.case_id)
            return case, stage_results
        except Exception as exc:
            logger.error(
                "Analysis pipeline failure for message '%s': %s",
                email.provider_message_id,
                str(exc),
                exc_info=True,
            )
            raise


# Global default instance and FastAPI dependency helper
default_pipeline = AnalysisPipeline()


def get_pipeline() -> AnalysisPipeline:
    """FastAPI dependency provider for the analysis pipeline."""
    return default_pipeline
