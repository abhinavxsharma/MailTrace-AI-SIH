"""Service layer implementing mailbox database operations."""

from typing import List, Optional
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.models.mailbox import Mailbox
from backend.app.schemas.mailbox import MailboxCreate, MailboxStatusUpdate


def create_mailbox(db: Session, mailbox_in: MailboxCreate) -> Mailbox:
    """Register a new mailbox in the database."""
    mailbox = Mailbox(
        provider=mailbox_in.provider,
        account_email=mailbox_in.account_email,
        status=mailbox_in.status.value,
    )
    db.add(mailbox)
    db.commit()
    db.refresh(mailbox)
    return mailbox


def get_mailbox(db: Session, mailbox_id: int) -> Optional[Mailbox]:
    """Fetch a mailbox by internal primary key."""
    return db.get(Mailbox, mailbox_id)


def list_mailboxes(db: Session, skip: int = 0, limit: int = 100) -> List[Mailbox]:
    """Retrieve all configured mailboxes with pagination, prioritizing active credentials."""
    stmt = (
        select(Mailbox)
        .order_by(Mailbox.credentials_data.isnot(None).desc(), Mailbox.created_at.desc())
        .offset(skip)
        .limit(limit)
    )
    return list(db.execute(stmt).scalars().all())


def update_mailbox_status(
    db: Session,
    mailbox: Mailbox,
    status_update: MailboxStatusUpdate,
) -> Mailbox:
    """Update status for a connected mailbox."""
    mailbox.status = status_update.status.value
    db.commit()
    db.refresh(mailbox)
    return mailbox
