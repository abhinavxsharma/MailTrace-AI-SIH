"""Gmail mailbox watch registration and renewal service."""

from datetime import datetime, timezone
from typing import Any, Dict
from googleapiclient.errors import HttpError
from sqlalchemy.orm import Session

from backend.app.core.config import settings
from backend.app.core.exceptions import MailTraceException
from backend.app.core.logging import logger
from backend.app.models.mailbox import Mailbox
from backend.app.services.gmail.client import build_gmail_service
from backend.app.services.gmail.token_store import TokenStore


def start_mailbox_watch(db: Session, mailbox: Mailbox) -> Dict[str, Any]:
    """Register or renew a Gmail push notification watch via Google Cloud Pub/Sub.

    Calls users().watch() and persists returned historyId and watch_expiration.

    Args:
        db: Active database session.
        mailbox: Target Gmail mailbox entity.

    Returns:
        Dictionary with watch status, history_id, and expiration timestamp.
    """
    if mailbox.provider.lower() != "gmail":
        raise MailTraceException(
            message=f"Mailbox ID {mailbox.id} is not a Gmail account (provider={mailbox.provider}).",
            code="INVALID_MAILBOX_PROVIDER",
            status_code=400,
        )

    creds = TokenStore.get_credentials(db=db, mailbox=mailbox)
    if not creds:
        raise MailTraceException(
            message=f"Mailbox '{mailbox.account_email}' has no valid OAuth credentials.",
            code="GMAIL_CREDENTIALS_MISSING",
            status_code=401,
        )

    topic = settings.google_pubsub_topic
    if not topic or not topic.startswith("projects/") or "/topics/" not in topic:
        raise MailTraceException(
            message="GOOGLE_PUBSUB_TOPIC is not configured or invalid. Expected format: projects/<PROJECT_ID>/topics/<TOPIC_ID>",
            code="INVALID_PUBSUB_TOPIC",
            status_code=500,
        )

    service = build_gmail_service(credentials=creds)

    watch_request_body = {
        "topicName": topic,
        "labelIds": ["INBOX"],
    }

    try:
        logger.info(
            "Initiating Gmail watch for mailbox '%s' with topic '%s'",
            mailbox.account_email,
            settings.google_pubsub_topic,
        )
        response = service.users().watch(userId="me", body=watch_request_body).execute()
    except HttpError as exc:
        logger.error("Gmail API watch request failed for mailbox '%s': %s", mailbox.account_email, str(exc))
        raise MailTraceException(
            message=f"Failed to establish Gmail watch: {exc.reason}",
            code="GMAIL_WATCH_ERROR",
            status_code=exc.status_code if hasattr(exc, "status_code") else 502,
        ) from exc

    history_id = str(response.get("historyId", ""))
    expiration_ms = response.get("expiration")

    watch_expiration = None
    if expiration_ms:
        try:
            watch_expiration = datetime.fromtimestamp(int(expiration_ms) / 1000.0, tz=timezone.utc)
        except (ValueError, TypeError):
            watch_expiration = None

    # Persist watch state
    mailbox.latest_history_id = history_id or mailbox.latest_history_id
    mailbox.watch_expiration = watch_expiration
    mailbox.updated_at = datetime.now(timezone.utc)
    db.add(mailbox)
    db.commit()
    db.refresh(mailbox)

    logger.info(
        "Successfully registered Gmail watch for '%s' (history_id=%s, expires=%s)",
        mailbox.account_email,
        mailbox.latest_history_id,
        mailbox.watch_expiration,
    )

    return {
        "status": "watching",
        "mailbox_id": mailbox.id,
        "account_email": mailbox.account_email,
        "history_id": mailbox.latest_history_id,
        "expiration": mailbox.watch_expiration.isoformat() if mailbox.watch_expiration else None,
        "topic": settings.google_pubsub_topic,
    }


def stop_mailbox_watch(db: Session, mailbox: Mailbox) -> Dict[str, Any]:
    """Deregister push notifications for a Gmail mailbox."""
    creds = TokenStore.get_credentials(db=db, mailbox=mailbox)
    if creds:
        try:
            service = build_gmail_service(credentials=creds)
            service.users().stop(userId="me").execute()
            logger.info("Stopped Gmail watch for mailbox '%s'", mailbox.account_email)
        except Exception as exc:
            logger.warning("Error stopping Gmail watch for '%s': %s", mailbox.account_email, str(exc))

    mailbox.watch_expiration = None
    mailbox.updated_at = datetime.now(timezone.utc)
    db.add(mailbox)
    db.commit()
    db.refresh(mailbox)

    return {
        "status": "stopped",
        "mailbox_id": mailbox.id,
        "account_email": mailbox.account_email,
    }
