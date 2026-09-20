"""SQLAlchemy model for connected mailboxes."""

from datetime import datetime, timezone
from typing import TYPE_CHECKING, List, Optional
from sqlalchemy import DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.db.database import Base
from backend.app.models.enums import MailboxStatus

if TYPE_CHECKING:
    from backend.app.models.alert import SecurityAlert
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
    latest_history_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    watch_expiration: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    credentials_data: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
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
    alerts: Mapped[List["SecurityAlert"]] = relationship(
        "SecurityAlert",
        back_populates="mailbox",
        cascade="all, delete-orphan",
    )


    @property
    def has_credentials(self) -> bool:
        """Indicate whether the mailbox has active OAuth credentials stored."""
        return bool(self.credentials_data)
