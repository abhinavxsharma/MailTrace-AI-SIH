"""API router for mailbox event ingestion."""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend.app.db.session import get_db
from backend.app.schemas.mail_event import MailEvent, MailEventResponse
from backend.app.services.mail_event_service import ingest_mail_event

router = APIRouter()


@router.post(
    "/events",
    response_model=MailEventResponse,
    status_code=status.HTTP_200_OK,
    summary="Ingest mailbox notification event",
)
def handle_mail_event(
    event: MailEvent,
    db: Session = Depends(get_db),
) -> MailEventResponse:
    """Ingest a normalized email event from a connected mailbox provider.

    Validates mailbox ownership, enforces message-level idempotency on
    (provider, provider_message_id), and initializes case records.
    Does not require raw MIME file uploads.
    """
    try:
        return ingest_mail_event(db=db, event=event)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
