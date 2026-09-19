"""SQLAlchemy model for email investigation cases."""

import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING, List, Optional
from sqlalchemy import CheckConstraint, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.db.database import Base
from backend.app.models.enums import CaseStatus, Classification

if TYPE_CHECKING:
    from backend.app.models.analysis import Analysis
    from backend.app.models.audit import AuditEvent
    from backend.app.models.mailbox import Mailbox


def generate_case_id() -> str:
    """Generate a unique, human-readable case identifier."""
    return f"case_{uuid.uuid4().hex[:12]}"


class Case(Base):
    """Investigation case tracking email threat analysis."""

    __tablename__ = "cases"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    case_id: Mapped[str] = mapped_column(
        String(64),
        unique=True,
        index=True,
        nullable=False,
        default=generate_case_id,
    )
    mailbox_id: Mapped[Optional[int]] = mapped_column(
        Integer,
        ForeignKey("mailboxes.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    provider: Mapped[str] = mapped_column(String(50), nullable=False)
    provider_message_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    thread_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    sender: Mapped[str] = mapped_column(String(255), nullable=False)
    recipient: Mapped[str] = mapped_column(String(255), nullable=False)
    subject: Mapped[str] = mapped_column(Text, nullable=False)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default=CaseStatus.NEW.value,
        index=True,
    )
    classification: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default=Classification.PENDING.value,
        index=True,
    )
    ai_confidence: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    risk_score: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

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
        CheckConstraint("risk_score IS NULL OR (risk_score >= 0 AND risk_score <= 100)", name="check_risk_score_range"),
        CheckConstraint("ai_confidence IS NULL OR (ai_confidence >= 0.0 AND ai_confidence <= 1.0)", name="check_ai_confidence_range"),
    )

    # Relationships
    mailbox: Mapped[Optional["Mailbox"]] = relationship("Mailbox", back_populates="cases")
    analyses: Mapped[List["Analysis"]] = relationship(
        "Analysis",
        back_populates="case",
        cascade="all, delete-orphan",
        order_by="Analysis.created_at.desc()",
    )
    audit_events: Mapped[List["AuditEvent"]] = relationship(
        "AuditEvent",
        back_populates="case",
        cascade="all, delete-orphan",
        order_by="AuditEvent.created_at.desc()",
    )
