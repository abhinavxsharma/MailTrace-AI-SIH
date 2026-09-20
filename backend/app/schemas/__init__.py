"""Pydantic schemas package."""

from backend.app.schemas.analysis import (
    AnalysisRead,
    AnalysisResult,
    AnalysisStartResponse,
    NormalizedEmail,
)
from backend.app.schemas.audit import AuditEventRead
from backend.app.schemas.case import (
    CaseAnalysisUpdate,
    CaseBase,
    CaseCreate,
    CaseRead,
    CaseStatusUpdate,
)
from backend.app.schemas.mail_event import (
    MailEvent,
    MailEventResponse,
    MailEventStatus,
    MailEventType,
)
from backend.app.schemas.alert import (
    SecurityAlertCreate,
    SecurityAlertRead,
    SecurityAlertStatusUpdate,
)
from backend.app.schemas.mailbox import (
    MailboxBase,
    MailboxCreate,
    MailboxRead,
    MailboxStatusUpdate,
)


__all__ = [
    "MailboxBase",
    "MailboxCreate",
    "MailboxStatusUpdate",
    "MailboxRead",
    "CaseBase",
    "CaseCreate",
    "CaseStatusUpdate",
    "CaseAnalysisUpdate",
    "CaseRead",
    "AnalysisRead",
    "AnalysisResult",
    "AnalysisStartResponse",
    "NormalizedEmail",
    "AuditEventRead",
    "MailEvent",
    "MailEventResponse",
    "MailEventType",
    "MailEventStatus",
    "SecurityAlertCreate",
    "SecurityAlertRead",
    "SecurityAlertStatusUpdate",
]
