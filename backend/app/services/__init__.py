"""Services package."""

from backend.app.services.analysis_pipeline import AnalysisPipeline, get_pipeline
from backend.app.services.case_service import (
    add_audit_event,
    create_case,
    get_case,
    get_case_analyses,
    get_case_audit_events,
    get_case_by_provider_message,
    list_cases,
    update_case_result,
    update_case_status,
)
from backend.app.services.mail_event_service import (
    get_mailbox_by_email,
    ingest_mail_event,
)
from backend.app.services.mailbox_service import (
    create_mailbox,
    get_mailbox,
    list_mailboxes,
    update_mailbox_status,
)
from backend.app.services.provider_client import MailProviderClient

__all__ = [
    "create_case",
    "get_case",
    "get_case_by_provider_message",
    "list_cases",
    "update_case_status",
    "update_case_result",
    "add_audit_event",
    "get_case_analyses",
    "get_case_audit_events",
    "create_mailbox",
    "get_mailbox",
    "get_mailbox_by_email",
    "list_mailboxes",
    "update_mailbox_status",
    "AnalysisPipeline",
    "get_pipeline",
    "MailProviderClient",
    "ingest_mail_event",
]
