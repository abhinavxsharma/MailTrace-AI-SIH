"""SQLAlchemy model for mailbox security threat alerts."""

import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING, List, Optional
from sqlalchemy import DateTime, Float, ForeignKey, Integer, JSON, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.db.database import Base
from backend.app.models.enums import AlertStatus

if TYPE_CHECKING:
    from backend.app.models.case import Case
    from backend.app.models.mailbox import Mailbox


def generate_alert_id() -> str:
    """Generate a unique, human-readable alert identifier."""
    return f"alt_{uuid.uuid4().hex[:12]}"


class SecurityAlert(Base):
    """Represents an automated threat detection alert for an incoming mailbox message."""

    __tablename__ = "security_alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    alert_id: Mapped[str] = mapped_column(
        String(64),
        unique=True,
        index=True,
        nullable=False,
        default=generate_alert_id,
    )
    mailbox_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("mailboxes.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    message_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    thread_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    case_id: Mapped[Optional[int]] = mapped_column(
        Integer,
        ForeignKey("cases.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    sender: Mapped[str] = mapped_column(String(255), nullable=False)
    sender_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    subject: Mapped[str] = mapped_column(Text, nullable=False)

    verdict: Mapped[str] = mapped_column(String(32), nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False)
    risk_level: Mapped[str] = mapped_column(String(32), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)

    title: Mapped[str] = mapped_column(String(255), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    reasons: Mapped[List[str]] = mapped_column(JSON, nullable=False, default=list)
    indicators: Mapped[List[str]] = mapped_column(JSON, nullable=False, default=list)
    recommended_action: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        default="Review email security preview before opening.",
    )

    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default=AlertStatus.UNREAD.value,
        index=True,
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

    __table_args__ = (
        UniqueConstraint("mailbox_id", "message_id", name="uq_mailbox_message_alert"),
    )

    # Relationships
    mailbox: Mapped["Mailbox"] = relationship("Mailbox", back_populates="alerts")
    case: Mapped[Optional["Case"]] = relationship("Case")
