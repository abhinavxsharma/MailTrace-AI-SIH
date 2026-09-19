"""API router for case management endpoints."""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.app.db.session import get_db
from backend.app.models.enums import CaseStatus, Classification
from backend.app.schemas.analysis import AnalysisRead
from backend.app.schemas.audit import AuditEventRead
from backend.app.schemas.case import (
    CaseAnalysisUpdate,
    CaseCreate,
    CaseRead,
    CaseStatusUpdate,
)
from backend.app.services import case_service

router = APIRouter()


@router.post(
    "",
    response_model=CaseRead,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new email case",
)
def create_case(case_in: CaseCreate, db: Session = Depends(get_db)) -> CaseRead:
    """Create an email investigation case from structured mailbox metadata."""
    try:
        return case_service.create_case(db=db, case_in=case_in)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get(
    "",
    response_model=List[CaseRead],
    summary="List investigation cases",
)
def list_cases(
    skip: int = Query(0, ge=0, description="Pagination offset"),
    limit: int = Query(100, ge=1, le=500, description="Pagination limit"),
    case_status: Optional[CaseStatus] = Query(None, alias="status", description="Filter by case status"),
    classification: Optional[Classification] = Query(None, description="Filter by classification"),
    db: Session = Depends(get_db),
) -> List[CaseRead]:
    """Retrieve list of investigation cases with optional filtering."""
    return case_service.list_cases(
        db=db,
        skip=skip,
        limit=limit,
        status=case_status,
        classification=classification,
    )


@router.get(
    "/{case_id}",
    response_model=CaseRead,
    summary="Get case by identifier",
)
def get_case(case_id: str, db: Session = Depends(get_db)) -> CaseRead:
    """Retrieve details of a single case by its unique public case_id or internal ID."""
    case = case_service.get_case(db=db, case_identifier=case_id)
    if not case:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found.")
    return case


@router.patch(
    "/{case_id}/status",
    response_model=CaseRead,
    summary="Update case status",
)
def update_case_status(
    case_id: str,
    status_update: CaseStatusUpdate,
    db: Session = Depends(get_db),
) -> CaseRead:
    """Update case lifecycle status and record an audit event."""
    case = case_service.get_case(db=db, case_identifier=case_id)
    if not case:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found.")
    return case_service.update_case_status(db=db, case=case, status_update=status_update)


@router.patch(
    "/{case_id}/result",
    response_model=CaseRead,
    summary="Update case analysis results",
)
def update_case_result(
    case_id: str,
    result_update: CaseAnalysisUpdate,
    db: Session = Depends(get_db),
) -> CaseRead:
    """Update threat classification, confidence, and risk score for a case."""
    case = case_service.get_case(db=db, case_identifier=case_id)
    if not case:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found.")
    try:
        return case_service.update_case_result(db=db, case=case, result_update=result_update)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get(
    "/{case_id}/analysis",
    response_model=List[AnalysisRead],
    summary="Get analysis history for a case",
)
def get_case_analysis(case_id: str, db: Session = Depends(get_db)) -> List[AnalysisRead]:
    """Retrieve all historical analysis determinations for a case."""
    case = case_service.get_case(db=db, case_identifier=case_id)
    if not case:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found.")
    return case_service.get_case_analyses(db=db, case=case)


@router.get(
    "/{case_id}/audit",
    response_model=List[AuditEventRead],
    summary="Get audit event logs for a case",
)
def get_case_audit(case_id: str, db: Session = Depends(get_db)) -> List[AuditEventRead]:
    """Retrieve full chronological audit trail for a case."""
    case = case_service.get_case(db=db, case_identifier=case_id)
    if not case:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found.")
    return case_service.get_case_audit_events(db=db, case=case)
