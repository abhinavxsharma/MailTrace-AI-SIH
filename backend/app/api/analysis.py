"""API router for analysis pipeline endpoints."""

from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from backend.app.db.session import get_db
from backend.app.models.enums import CaseStatus
from backend.app.schemas.analysis import AnalysisStartResponse, NormalizedEmail
from backend.app.services.analysis_pipeline import AnalysisPipeline, get_pipeline

router = APIRouter()


@router.post(
    "",
    response_model=AnalysisStartResponse,
    status_code=status.HTTP_200_OK,
    summary="Start email analysis pipeline",
)
def start_analysis(
    email: NormalizedEmail,
    db: Session = Depends(get_db),
    pipeline: AnalysisPipeline = Depends(get_pipeline),
) -> AnalysisStartResponse:
    """Ingest a normalized email and trigger the multi-stage security analysis pipeline in memory.

    Accepts structured JSON metadata directly. Does NOT accept raw .eml file uploads.
    """
    case, _ = pipeline.run(db=db, email=email)
    return AnalysisStartResponse(
        case_id=case.case_id,
        status=CaseStatus(case.status),
        message="Analysis pipeline started",
    )
