"""Synchronization service connecting Gmail notifications directly to the Pre-Open Scan pipeline."""

from datetime import datetime, timezone
from typing import Any, Dict, Optional
from sqlalchemy.orm import Session

from backend.app.core.logging import logger
from backend.app.db.session import SessionLocal
from backend.app.models.alert import SecurityAlert, generate_alert_id
from backend.app.models.audit import AuditEvent
from backend.app.models.case import Case, generate_case_id
from backend.app.models.enums import AlertStatus, CaseStatus
from backend.app.models.mailbox import Mailbox
from backend.app.services.analysis_pipeline import AnalysisPipeline
from backend.app.services.case_service import get_case_by_provider_message
from backend.app.services.gmail.client import build_gmail_service, fetch_gmail_message_resource
from backend.app.services.gmail.history import list_new_messages_from_history
from backend.app.services.gmail.message_parser import parse_gmail_message
from backend.app.services.gmail.token_store import TokenStore
from backend.app.services.gmail.watcher import renew_mailbox_watch_if_needed
from backend.app.services.mail_event_service import get_mailbox_by_email
from backend.app.services.pre_open_scan import scan_email_pre_open


def sync_gmail_mailbox(
    account_email: str,
    notification_history_id: Optional[str] = None,
    db_session: Optional[Session] = None,
    pipeline: Optional[AnalysisPipeline] = None,
) -> Dict[str, Any]:
    """Synchronize new emails for a Gmail mailbox and execute fast pre-open threat detection.

    Processes arriving Gmail messages in-memory, evaluates them against the
    Pre-Open Threat Scan engine, generates SecurityAlert records according
    to the alert policy, and maintains linkage to investigation cases.

    Args:
        account_email: Connected Gmail email address.
        notification_history_id: Optional history ID included in Pub/Sub push notification.
        db_session: Optional active DB session (creates one if not provided).
        pipeline: Optional AnalysisPipeline instance (for full deep pipeline runs if requested).

    Returns:
        Summary dict of synchronization metrics and state.
    """
    should_close_db = db_session is None
    db = db_session if db_session is not None else SessionLocal()

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

        # Attempt safe watch renewal if nearing expiry
        try:
            renew_mailbox_watch_if_needed(db=db, mailbox=mailbox)
        except Exception as exc:
            logger.warning("Watch renewal check skipped for '%s': %s", account_email, str(exc))

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
            # 1. Enforce message-level idempotency on (mailbox_id, message_id)
            existing_alert = (
                db.query(SecurityAlert)
                .filter(SecurityAlert.mailbox_id == mailbox.id, SecurityAlert.message_id == msg_id)
                .first()
            )
            existing_case = get_case_by_provider_message(
                db=db,
                provider="gmail",
                provider_message_id=msg_id,
            )

            if existing_alert or existing_case:
                logger.info(
                    "Duplicate Gmail message '%s' skipped for '%s' (alert=%s, case=%s)",
                    msg_id,
                    account_email,
                    existing_alert.alert_id if existing_alert else None,
                    existing_case.case_id if existing_case else None,
                )
                duplicate_count += 1
                if existing_case:
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
            try:
                logger.info("Fetching Gmail message '%s' for in-memory threat scan", msg_id)
                msg_resource = fetch_gmail_message_resource(service=service, message_id=msg_id)

                # 3. Parse into canonical NormalizedEmail schema
                normalized_email = parse_gmail_message(
                    message_resource=msg_resource,
                    mailbox_id=mailbox.id,
                )

                # 4. Fast in-memory Pre-Open Threat Scan (<50ms, no heavy RDAP/GeoIP)
                pre_scan = scan_email_pre_open(email=normalized_email)


                risk_level = pre_scan.risk_level.value

                # 5. Determine Alert Policy Presentation
                if risk_level == "CRITICAL":
                    title = f"CRITICAL THREAT: {pre_scan.subject}"
                    summary = (
                        "MAILTRACE detected a critical threat before you opened it. "
                        "Do not open or interact with this email."
                    )
                elif risk_level == "HIGH":
                    title = f"HIGH RISK: {pre_scan.subject}"
                    summary = (
                        "MAILTRACE detected a high-risk email before you opened it. "
                        "Potential phishing lure, impersonation, or credential theft."
                    )
                elif risk_level == "MEDIUM":
                    title = f"SUSPICIOUS EMAIL: {pre_scan.subject}"
                    summary = (
                        "Suspicious indicators or authentication failures detected. "
                        "Proceed with caution."
                    )
                else:
                    title = f"Clean: {pre_scan.subject}"
                    summary = "Pre-open security check passed. No immediate threats detected."

                # 6. Create Case record tracking message threat state
                case = Case(
                    case_id=generate_case_id(),
                    mailbox_id=mailbox.id,
                    provider="gmail",
                    provider_message_id=msg_id,
                    thread_id=normalized_email.thread_id,
                    sender=normalized_email.sender,
                    recipient=normalized_email.recipient,
                    subject=normalized_email.subject,
                    received_at=normalized_email.received_at or datetime.now(timezone.utc),
                    status=CaseStatus.ANALYZED.value,
                    classification=pre_scan.verdict.value,
                    ai_confidence=pre_scan.confidence,
                    risk_score=pre_scan.risk_score,
                )
                db.add(case)
                db.flush()

                db.add(
                    AuditEvent(
                        case_id=case.id,
                        event_type="AUTOMATED_PRE_OPEN_SCAN",
                        message=(
                            f"Pre-open threat scan completed for message '{msg_id}'. "
                            f"Risk: {pre_scan.risk_score} ({risk_level}), Verdict: {pre_scan.verdict.value}."
                        ),
                    )
                )

                # 7. Create SecurityAlert linked to Case
                alert = SecurityAlert(
                    alert_id=generate_alert_id(),
                    mailbox_id=mailbox.id,
                    message_id=msg_id,
                    thread_id=normalized_email.thread_id,
                    case_id=case.id,
                    sender=pre_scan.sender,
                    sender_name=pre_scan.sender_name,
                    subject=pre_scan.subject,
                    verdict=pre_scan.verdict.value,
                    risk_score=pre_scan.risk_score,
                    risk_level=risk_level,
                    confidence=pre_scan.confidence,
                    title=title,
                    summary=summary,
                    reasons=pre_scan.reasons,
                    indicators=pre_scan.indicators,
                    recommended_action=pre_scan.recommended_action,
                    status=AlertStatus.UNREAD.value,
                )
                db.add(alert)
                db.commit()

                # 8. Real-Time Broadcast to Connected Clients (<200ms latency)
                try:
                    from backend.app.services.event_broadcaster import broadcast_mailbox_event
                    from backend.app.schemas.alert import SecurityAlertRead

                    alert_payload = SecurityAlertRead.model_validate(alert).model_dump(mode="json")
                    msg_payload = {
                        "id": msg_id,
                        "thread_id": normalized_email.thread_id,
                        "from": normalized_email.sender,
                        "subject": normalized_email.subject,
                        "date": normalized_email.received_at.isoformat() if normalized_email.received_at else None,
                        "snippet": normalized_email.body_snippet or summary,
                    }
                    broadcast_mailbox_event(
                        mailbox_id=mailbox.id,
                        event_type="NEW_ALERT",
                        payload={"alert": alert_payload, "message": msg_payload},
                    )
                except Exception as bcast_err:
                    logger.debug("Failed to broadcast alert event: %s", bcast_err)

                # If deep pipeline explicitly requested (e.g. specialized test execution)
                if pipeline is not None:
                    pipeline.run(db=db, email=normalized_email)

                processed_count += 1
                logger.info(
                    "Gmail message '%s' pre-scanned successfully: risk=%d (%s), alert=%s, case=%s",
                    msg_id,
                    pre_scan.risk_score,
                    risk_level,
                    alert.alert_id,
                    case.case_id,
                )

            except Exception as item_err:
                db.rollback()
                logger.error(
                    "Failed to process Gmail message '%s' for '%s': %s",
                    msg_id,
                    account_email,
                    str(item_err),
                    exc_info=True,
                )

        # 8. Advance stored history ID
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
