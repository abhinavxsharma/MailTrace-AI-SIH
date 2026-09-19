"""Service layer implementing case management business and database logic."""

from typing import List, Optional, Union
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.core.logging import logger
from backend.app.models.analysis import Analysis
from backend.app.models.audit import AuditEvent
from backend.app.models.case import Case, generate_case_id
from backend.app.models.enums import CaseStatus, Classification
from backend.app.models.mailbox import Mailbox
from backend.app.schemas.case import CaseAnalysisUpdate, CaseCreate, CaseStatusUpdate


def create_case(db: Session, case_in: CaseCreate) -> Case:
    """Create a new case from structured email metadata."""
    if case_in.mailbox_id is not None:
        mailbox = db.get(Mailbox, case_in.mailbox_id)
        if not mailbox:
            raise ValueError(f"Mailbox with id {case_in.mailbox_id} does not exist.")

    case = Case(
        case_id=generate_case_id(),
        mailbox_id=case_in.mailbox_id,
        provider=case_in.provider,
        provider_message_id=case_in.provider_message_id,
        thread_id=case_in.thread_id,
        sender=case_in.sender,
        recipient=case_in.recipient,
        subject=case_in.subject,
        received_at=case_in.received_at,
        status=CaseStatus.NEW.value,
        classification=Classification.PENDING.value,
    )
    db.add(case)
    db.flush()

    # Create initial audit log entry
    audit_event = AuditEvent(
        case_id=case.id,
        event_type="CASE_CREATED",
        message=f"Case {case.case_id} created for message '{case.provider_message_id}' via {case.provider}.",
    )
    db.add(audit_event)

    db.commit()
    db.refresh(case)
    logger.info("Case created: %s for message '%s'", case.case_id, case.provider_message_id)
    return case


def get_case(db: Session, case_identifier: Union[str, int]) -> Optional[Case]:
    """Retrieve a case by public case_id or internal primary key ID."""
    if isinstance(case_identifier, int) or (isinstance(case_identifier, str) and case_identifier.isdigit()):
        # Try numeric ID lookup
        case = db.get(Case, int(case_identifier))
        if case:
            return case

    # Fallback to unique public case_id
    stmt = select(Case).where(Case.case_id == str(case_identifier))
    return db.execute(stmt).scalar_one_or_none()


def get_case_by_provider_message(
    db: Session,
    provider: str,
    provider_message_id: str,
) -> Optional[Case]:
    """Look up an existing case by provider name and provider message ID."""
    stmt = select(Case).where(
        Case.provider == provider,
        Case.provider_message_id == provider_message_id,
    )
    return db.execute(stmt).scalar_one_or_none()


def list_cases(
    db: Session,
    skip: int = 0,
    limit: int = 100,
    status: Optional[CaseStatus] = None,
    classification: Optional[Classification] = None,
) -> List[Case]:
    """List investigation cases with optional status and classification filtering."""
    stmt = select(Case).order_by(Case.created_at.desc())

    if status:
        stmt = stmt.where(Case.status == status.value)
    if classification:
        stmt = stmt.where(Case.classification == classification.value)

    stmt = stmt.offset(skip).limit(limit)
    return list(db.execute(stmt).scalars().all())


def update_case_status(db: Session, case: Case, status_update: CaseStatusUpdate) -> Case:
    """Update case lifecycle status and record an audit log event."""
    old_status = case.status
    case.status = status_update.status.value

    audit_event = AuditEvent(
        case_id=case.id,
        event_type="STATUS_UPDATED",
        message=f"Case status changed from {old_status} to {case.status}.",
    )
    db.add(audit_event)
    db.commit()
    db.refresh(case)
    return case


def update_case_result(db: Session, case: Case, result_update: CaseAnalysisUpdate) -> Case:
    """Apply analysis results, store an analysis record, and update case classification."""
    if result_update.risk_score is not None and not (0 <= result_update.risk_score <= 100):
        raise ValueError("risk_score must be between 0 and 100.")
    if result_update.ai_confidence is not None and not (0.0 <= result_update.ai_confidence <= 1.0):
        raise ValueError("ai_confidence must be between 0.0 and 1.0.")

    case.classification = result_update.classification.value
    case.ai_confidence = result_update.ai_confidence
    case.risk_score = result_update.risk_score

    # Transition status to COMPLETED if previously in active stages
    if case.status in (CaseStatus.NEW.value, CaseStatus.PROCESSING.value):
        case.status = CaseStatus.COMPLETED.value

    # Insert historical analysis snapshot
    analysis = Analysis(
        case_id=case.id,
        classification=result_update.classification.value,
        ai_confidence=result_update.ai_confidence,
        risk_score=result_update.risk_score,
    )
    db.add(analysis)

    # Record audit log
    audit_event = AuditEvent(
        case_id=case.id,
        event_type="ANALYSIS_UPDATED",
        message=(
            f"Case analysis updated: classification={result_update.classification.value}, "
            f"risk_score={result_update.risk_score}, confidence={result_update.ai_confidence}."
        ),
    )
    db.add(audit_event)

    db.commit()
    db.refresh(case)
    return case


def add_audit_event(db: Session, case: Case, event_type: str, message: str) -> AuditEvent:
    """Record an audit event associated with a specific case."""
    audit_event = AuditEvent(
        case_id=case.id,
        event_type=event_type,
        message=message,
    )
    db.add(audit_event)
    db.commit()
    db.refresh(audit_event)
    return audit_event


def get_case_analyses(db: Session, case: Case) -> List[Analysis]:
    """Retrieve all analysis determinations associated with a case."""
    stmt = select(Analysis).where(Analysis.case_id == case.id).order_by(Analysis.created_at.desc())
    return list(db.execute(stmt).scalars().all())


def get_case_audit_events(db: Session, case: Case) -> List[AuditEvent]:
    """Retrieve the complete audit history for a case."""
    stmt = select(AuditEvent).where(AuditEvent.case_id == case.id).order_by(AuditEvent.created_at.desc())
    return list(db.execute(stmt).scalars().all())
