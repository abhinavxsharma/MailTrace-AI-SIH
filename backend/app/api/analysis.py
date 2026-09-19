from datetime import datetime, timezone
import hashlib
from typing import Any, Dict
from fastapi import APIRouter, Depends, HTTPException, status
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
    """Ingest a normalized email and trigger the multi-stage security analysis pipeline in memory."""
    case, _ = pipeline.run(db=db, email=email)
    return AnalysisStartResponse(
        case_id=case.case_id,
        status=CaseStatus(case.status),
        message="Analysis pipeline started",
    )


@router.post(
    "/raw-eml",
    status_code=status.HTTP_200_OK,
    summary="Ingest, parse, and analyze raw .eml RFC 822 email text in memory",
)
def analyze_raw_eml(
    payload: Dict[str, Any],
    db: Session = Depends(get_db),
    pipeline: AnalysisPipeline = Depends(get_pipeline),
) -> Dict[str, Any]:
    """Parse raw .eml content entirely in memory without writing to disk."""
    raw_content = payload.get("raw_eml", "")
    filename = payload.get("filename", "evidence.eml")
    if not raw_content or not str(raw_content).strip():
        raise HTTPException(status_code=400, detail="raw_eml content is required.")

    from forensics.email_parser.parser import parse_email

    sha256_hash = hashlib.sha256(raw_content.encode("utf-8", errors="replace")).hexdigest()
    parsed = parse_email(raw_content)

    headers_list = [
        {"name": h.name, "value": h.normalized_value or h.original_value}
        for h in parsed.headers
    ]

    recipient_val = parsed.to_addresses[0].email if parsed.to_addresses else "unknown"
    sender_val = parsed.from_address.email if parsed.from_address else "unknown"

    norm = NormalizedEmail(
        provider="eml_upload",
        provider_message_id=filename,
        sender=sender_val,
        recipient=recipient_val,
        subject=parsed.subject or "(No Subject)",
        body=parsed.body_text or "",
        headers=headers_list,
        received_at=parsed.date or datetime.now(timezone.utc),
    )

    case, stage_results = pipeline.run(db=db, email=norm)

    return {
        "sha256": sha256_hash,
        "filename": filename,
        "case": {
            "id": case.id,
            "case_id": case.case_id,
            "status": case.status,
            "classification": case.classification,
            "ai_confidence": case.ai_confidence,
            "risk_score": case.risk_score,
            "created_at": case.created_at.isoformat() if case.created_at else None,
        },
        "analysis": {
            "classification": case.classification,
            "ai_confidence": case.ai_confidence,
            "risk_score": case.risk_score,
            "forensics": stage_results.get("forensics", {}),
            "authentication": stage_results.get("authentication", {}),
            "ml": stage_results.get("ml", {}),
            "intelligence": stage_results.get("intelligence", {}),
            "correlation": stage_results.get("correlation", {}),
            "risk": stage_results.get("risk", {}),
        },
    }

