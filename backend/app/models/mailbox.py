"""SQLAlchemy model for connected mailboxes."""

from datetime import datetime, timezone
from typing import TYPE_CHECKING, List
from sqlalchemy import DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.db.database import Base
from backend.app.models.enums import MailboxStatus

if TYPE_CHECKING:
    from backend.app.models.case import Case


class Mailbox(Base):
    """Represents an integrated user or organization mailbox."""

    __tablename__ = "mailboxes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    provider: Mapped[str] = mapped_column(String(50), nullable=False)
    account_email: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default=MailboxStatus.CONNECTED.value,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    cases: Mapped[List["Case"]] = relationship(
        "Case",
        back_populates="mailbox",
        cascade="all, delete-orphan",
    )
