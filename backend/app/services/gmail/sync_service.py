"""Synchronization service connecting Gmail notifications directly to the AnalysisPipeline."""

from datetime import datetime, timezone
from typing import Any, Dict, Optional
from sqlalchemy.orm import Session

from backend.app.core.logging import logger
from backend.app.db.session import SessionLocal
from backend.app.models.audit import AuditEvent
from backend.app.models.mailbox import Mailbox
from backend.app.services.analysis_pipeline import AnalysisPipeline, default_pipeline
from backend.app.services.case_service import get_case_by_provider_message
from backend.app.services.gmail.client import build_gmail_service, fetch_gmail_message_resource
from backend.app.services.gmail.history import list_new_messages_from_history
from backend.app.services.gmail.message_parser import parse_gmail_message
from backend.app.services.gmail.token_store import TokenStore
from backend.app.services.mail_event_service import get_mailbox_by_email


def sync_gmail_mailbox(
    account_email: str,
    notification_history_id: Optional[str] = None,
    db_session: Optional[Session] = None,
    pipeline: Optional[AnalysisPipeline] = None,
) -> Dict[str, Any]:
    """Synchronize new emails for a Gmail mailbox and execute in-memory analysis pipeline.

    Args:
        account_email: Connected Gmail email address.
        notification_history_id: Optional history ID included in Pub/Sub push notification.
        db_session: Optional active DB session (creates one if not provided).
        pipeline: Optional AnalysisPipeline instance (defaults to global pipeline).

    Returns:
        Summary dict of synchronization metrics and state.
    """
    should_close_db = db_session is None
    db = db_session if db_session is not None else SessionLocal()
    active_pipeline = pipeline or default_pipeline

    try:
        mailbox = get_mailbox_by_email(db=db, account_email=account_email)
        if not mailbox:
            logger.warning("Pub/Sub sync skipped: No mailbox found for account '%s'", account_email)
            return {"status": "skipped", "reason": "mailbox_not_found"}

        if mailbox.provider.lower() != "gmail":
            logger.warning("Pub/Sub sync skipped: Mailbox '%s' is not a Gmail provider", account_email)
            return {"status": "skipped", "reason": "invalid_provider"}

        creds = TokenStore.get_credentials(db=db, mailbox=mailbox)
        if not creds:
            logger.warning("Pub/Sub sync skipped: No valid credentials for '%s'", account_email)
            return {"status": "skipped", "reason": "missing_credentials"}

        service = build_gmail_service(credentials=creds)

        # Baseline history ID
        start_history_id = mailbox.latest_history_id
        if not start_history_id:
            if notification_history_id:
                start_history_id = str(notification_history_id)
            else:
                profile = service.users().getProfile(userId="me").execute()
                start_history_id = str(profile.get("historyId", "1"))

        logger.info(
            "Starting Gmail sync for '%s' from history ID %s",
            account_email,
            start_history_id,
        )

        new_message_ids, new_history_id = list_new_messages_from_history(
            service=service,
            start_history_id=start_history_id,
        )

        processed_count = 0
        duplicate_count = 0

        for msg_id in new_message_ids:
            # 1. Enforce message-level idempotency on (provider, provider_message_id)
            existing_case = get_case_by_provider_message(
                db=db,
                provider="gmail",
                provider_message_id=msg_id,
            )

            if existing_case:
                logger.info(
                    "Duplicate Gmail message '%s' skipped. Existing case: %s",
                    msg_id,
                    existing_case.case_id,
                )
                duplicate_count += 1
                db.add(
                    AuditEvent(
                        case_id=existing_case.id,
                        event_type="DUPLICATE_GMAIL_NOTIFICATION",
                        message=f"Duplicate notification received for Gmail message '{msg_id}'.",
                    )
                )
                db.commit()
                continue

            # 2. Fetch structured message in memory without disk storage
            logger.info("Fetching Gmail message '%s' for in-memory analysis", msg_id)
            msg_resource = fetch_gmail_message_resource(service=service, message_id=msg_id)

            # 3. Parse into canonical NormalizedEmail schema
            normalized_email = parse_gmail_message(
                message_resource=msg_resource,
                mailbox_id=mailbox.id,
            )

            # 4. Ingest directly into AnalysisPipeline
            logger.info(
                "Handing off message '%s' (subject: '%s') to AnalysisPipeline",
                msg_id,
                normalized_email.subject,
            )
            case, stage_results = active_pipeline.run(db=db, email=normalized_email)
            processed_count += 1

            logger.info(
                "Gmail message '%s' processed successfully into case %s (risk score: %s)",
                msg_id,
                case.case_id,
                case.risk_score,
            )

        # 5. Advance stored history ID
        mailbox.latest_history_id = new_history_id
        mailbox.updated_at = datetime.now(timezone.utc)
        db.add(mailbox)
        db.commit()
        db.refresh(mailbox)

        logger.info(
            "Completed Gmail sync for '%s': %d processed, %d duplicates, new history ID %s",
            account_email,
            processed_count,
            duplicate_count,
            new_history_id,
        )

        return {
            "status": "success",
            "account_email": account_email,
            "messages_processed": processed_count,
            "duplicates_skipped": duplicate_count,
            "latest_history_id": new_history_id,
        }

    finally:
        if should_close_db:
            db.close()
