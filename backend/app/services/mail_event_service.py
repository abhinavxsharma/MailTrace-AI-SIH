"""Service layer for ingesting and processing mailbox event notifications."""

from datetime import datetime, timezone
from typing import Optional
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.core.logging import logger
from backend.app.models.audit import AuditEvent
from backend.app.models.case import Case, generate_case_id
from backend.app.models.enums import CaseStatus, Classification
from backend.app.models.mailbox import Mailbox
from backend.app.schemas.mail_event import MailEvent, MailEventResponse, MailEventStatus, MailEventType
from backend.app.services.case_service import get_case_by_provider_message


def get_mailbox_by_email(db: Session, account_email: str) -> Optional[Mailbox]:
    """Retrieve registered mailbox by account email address."""
    stmt = select(Mailbox).where(Mailbox.account_email == account_email)
    return db.execute(stmt).scalar_one_or_none()


def ingest_mail_event(db: Session, event: MailEvent) -> MailEventResponse:
    """Ingest a normalized mail event with idempotency and mailbox verification.

    Args:
        db: Active database session.
        event: Ingested mail notification event.

    Returns:
        MailEventResponse indicating whether the event was accepted or duplicate.

    Raises:
        ValueError: If the associated mailbox does not exist.
    """
    logger.info(
        "Ingesting mail event '%s' for message '%s' from account '%s' (provider: %s)",
        event.event_type.value,
        event.provider_message_id,
        event.account_email,
        event.provider,
    )

    # 1. Mailbox relationship verification
    mailbox = get_mailbox_by_email(db=db, account_email=event.account_email)
    if not mailbox:
        logger.warning(
            "Rejected mail event: Mailbox for account '%s' does not exist.",
            event.account_email,
        )
        raise ValueError(
            f"Mailbox for account '{event.account_email}' does not exist. "
            "Please register the mailbox first."
        )

    # 2. Idempotency check: (provider, provider_message_id)
    existing_case = get_case_by_provider_message(
        db=db,
        provider=event.provider,
        provider_message_id=event.provider_message_id,
    )

    if existing_case:
        logger.info(
            "Duplicate event detected for message '%s'. Existing case: %s",
            event.provider_message_id,
            existing_case.case_id,
        )
        # Log duplicate audit event without creating a duplicate case
        db.add(
            AuditEvent(
                case_id=existing_case.id,
                event_type="DUPLICATE_MAIL_EVENT",
                message=(
                    f"Duplicate mail event '{event.event_type.value}' received for message "
                    f"'{event.provider_message_id}'."
                ),
            )
        )
        db.commit()

        return MailEventResponse(
            status=MailEventStatus.DUPLICATE,
            provider=event.provider,
            provider_message_id=event.provider_message_id,
            case_id=existing_case.case_id,
            mailbox_id=mailbox.id,
            message="Duplicate event: case already exists for this message",
        )

    # 3. New message handling: create case in NEW status pending retrieval
    if event.event_type == MailEventType.NEW_MESSAGE:
        case = Case(
            case_id=generate_case_id(),
            mailbox_id=mailbox.id,
            provider=event.provider,
            provider_message_id=event.provider_message_id,
            thread_id=event.thread_id,
            sender="pending@mailtrace.internal",
            recipient=event.account_email,
            subject="Pending Message Retrieval",
            received_at=event.received_at or datetime.now(timezone.utc),
            status=CaseStatus.NEW.value,
            classification=Classification.PENDING.value,
        )
        db.add(case)
        db.flush()

        db.add(
            AuditEvent(
                case_id=case.id,
                event_type="MAIL_EVENT_RECEIVED",
                message=(
                    f"Mail event '{event.event_type.value}' received for message "
                    f"'{event.provider_message_id}' from account '{event.account_email}'. "
                    "Case initialized pending provider connector retrieval."
                ),
            )
        )
        db.commit()
        db.refresh(case)

        logger.info(
            "Accepted mail event and created case %s for message %s",
            case.case_id,
            event.provider_message_id,
        )

        return MailEventResponse(
            status=MailEventStatus.ACCEPTED,
            provider=event.provider,
            provider_message_id=event.provider_message_id,
            case_id=case.case_id,
            mailbox_id=mailbox.id,
            message="Event accepted for processing",
        )

    # 4. Other event notifications (MESSAGE_UPDATED, MESSAGE_DELETED)
    return MailEventResponse(
        status=MailEventStatus.ACCEPTED,
        provider=event.provider,
        provider_message_id=event.provider_message_id,
        case_id=None,
        mailbox_id=mailbox.id,
        message=f"Event '{event.event_type.value}' processed",
    )
