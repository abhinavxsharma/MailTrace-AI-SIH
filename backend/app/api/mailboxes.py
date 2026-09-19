"""API router for mailbox database management."""

from typing import List
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.app.db.session import get_db
from backend.app.schemas.mailbox import (
    MailboxCreate,
    MailboxRead,
    MailboxStatusUpdate,
)
from backend.app.services import mailbox_service

router = APIRouter()


@router.post(
    "",
    response_model=MailboxRead,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new mailbox",
)
def create_mailbox(
    mailbox_in: MailboxCreate,
    db: Session = Depends(get_db),
) -> MailboxRead:
    """Register a mailbox record in the database."""
    return mailbox_service.create_mailbox(db=db, mailbox_in=mailbox_in)


@router.get(
    "",
    response_model=List[MailboxRead],
    summary="List all mailboxes",
)
def list_mailboxes(
    skip: int = Query(0, ge=0, description="Pagination offset"),
    limit: int = Query(100, ge=1, le=500, description="Pagination limit"),
    db: Session = Depends(get_db),
) -> List[MailboxRead]:
    """Retrieve list of registered mailboxes."""
    return mailbox_service.list_mailboxes(db=db, skip=skip, limit=limit)


@router.get(
    "/{mailbox_id}",
    response_model=MailboxRead,
    summary="Get mailbox by ID",
)
def get_mailbox(
    mailbox_id: int,
    db: Session = Depends(get_db),
) -> MailboxRead:
    """Retrieve details for a single registered mailbox."""
    mailbox = mailbox_service.get_mailbox(db=db, mailbox_id=mailbox_id)
    if not mailbox:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Mailbox not found.",
        )
    return mailbox


@router.patch(
    "/{mailbox_id}/status",
    response_model=MailboxRead,
    summary="Update mailbox status",
)
def update_mailbox_status(
    mailbox_id: int,
    status_update: MailboxStatusUpdate,
    db: Session = Depends(get_db),
) -> MailboxRead:
    """Update operational status for a mailbox."""
    mailbox = mailbox_service.get_mailbox(db=db, mailbox_id=mailbox_id)
    if not mailbox:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Mailbox not found.",
        )
    return mailbox_service.update_mailbox_status(
        db=db,
        mailbox=mailbox,
        status_update=status_update,
    )
