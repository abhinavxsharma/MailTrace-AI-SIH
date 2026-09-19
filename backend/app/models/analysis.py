"""SQLAlchemy model for case threat analysis results."""

from datetime import datetime, timezone
from typing import TYPE_CHECKING, Optional, Any
from sqlalchemy import CheckConstraint, DateTime, Float, ForeignKey, Integer, JSON, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.db.database import Base
from backend.app.models.enums import Classification

if TYPE_CHECKING:
    from backend.app.models.case import Case


class Analysis(Base):
    """Stores threat analysis determinations, confidence, risk scoring, and stage outputs."""

    __tablename__ = "analyses"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    case_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("cases.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    classification: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default=Classification.PENDING.value,
    )
    ai_confidence: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    risk_score: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    # Structured stage execution results
    forensics: Mapped[Optional[dict[str, Any]]] = mapped_column(JSON, nullable=True, default=dict)
    authentication: Mapped[Optional[dict[str, Any]]] = mapped_column(JSON, nullable=True, default=dict)
    ml: Mapped[Optional[dict[str, Any]]] = mapped_column(JSON, nullable=True, default=dict)
    intelligence: Mapped[Optional[dict[str, Any]]] = mapped_column(JSON, nullable=True, default=dict)
    correlation: Mapped[Optional[dict[str, Any]]] = mapped_column(JSON, nullable=True, default=dict)
    risk: Mapped[Optional[dict[str, Any]]] = mapped_column(JSON, nullable=True, default=dict)

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
        CheckConstraint("risk_score IS NULL OR (risk_score >= 0 AND risk_score <= 100)", name="check_analysis_risk_score_range"),
        CheckConstraint("ai_confidence IS NULL OR (ai_confidence >= 0.0 AND ai_confidence <= 1.0)", name="check_analysis_ai_confidence_range"),
    )

    # Relationships
    case: Mapped["Case"] = relationship("Case", back_populates="analyses")
