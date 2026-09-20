from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from backend.app.db.session import get_db
from backend.app.core.logging import logger
from backend.app.models.alert import SecurityAlert
from backend.app.models.enums import AlertStatus, MailboxStatus
from backend.app.schemas.alert import SecurityAlertRead
from backend.app.schemas.mailbox import (
    BlockSenderResponse,
    MailboxCreate,
    MailboxRead,
    MailboxStatusUpdate,
    ReportSpamResponse,
    TrashMessageResponse,
)
from backend.app.schemas.pre_open import PreOpenScanResponse
from backend.app.services import mailbox_service

router = APIRouter()



@router.post(
    "",
    response_model=MailboxRead,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new mailbox",
)
def create_mailbox(
    mailbox_in: MailboxCreate,
    db: Session = Depends(get_db),
) -> MailboxRead:
    """Register a mailbox record in the database."""
    return mailbox_service.create_mailbox(db=db, mailbox_in=mailbox_in)


@router.get(
    "",
    response_model=List[MailboxRead],
    summary="List all mailboxes",
)
def list_mailboxes(
    skip: int = Query(0, ge=0, description="Pagination offset"),
    limit: int = Query(100, ge=1, le=500, description="Pagination limit"),
    db: Session = Depends(get_db),
) -> List[MailboxRead]:
    """Retrieve list of registered mailboxes."""
    return mailbox_service.list_mailboxes(db=db, skip=skip, limit=limit)


@router.get(
    "/{mailbox_id}",
    response_model=MailboxRead,
    summary="Get mailbox by ID",
)
def get_mailbox(
    mailbox_id: int,
    db: Session = Depends(get_db),
) -> MailboxRead:
    """Retrieve details for a single registered mailbox."""
    mailbox = mailbox_service.get_mailbox(db=db, mailbox_id=mailbox_id)
    if not mailbox:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Mailbox not found.",
        )
    return mailbox


@router.patch(
    "/{mailbox_id}/status",
    response_model=MailboxRead,
    summary="Update mailbox status",
)
def update_mailbox_status(
    mailbox_id: int,
    status_update: MailboxStatusUpdate,
    db: Session = Depends(get_db),
) -> MailboxRead:
    """Update operational status for a mailbox."""
    mailbox = mailbox_service.get_mailbox(db=db, mailbox_id=mailbox_id)
    if not mailbox:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Mailbox not found.",
        )
    return mailbox_service.update_mailbox_status(
        db=db,
        mailbox=mailbox,
        status_update=status_update,
    )


@router.post(
    "/{mailbox_id}/disconnect",
    response_model=MailboxRead,
    summary="Disconnect mailbox and purge OAuth credentials",
)
def disconnect_mailbox(
    mailbox_id: int,
    db: Session = Depends(get_db),
) -> MailboxRead:
    """Revoke local OAuth token and mark mailbox as disconnected."""
    mailbox = mailbox_service.get_mailbox(db=db, mailbox_id=mailbox_id)
    if not mailbox:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Mailbox not found.",
        )
    mailbox.credentials_data = None
    mailbox.status = MailboxStatus.DISCONNECTED.value
    db.commit()
    db.refresh(mailbox)
    return mailbox


@router.post(
    "/{mailbox_id}/watch",
    status_code=status.HTTP_200_OK,
    summary="Start or renew mailbox push watch",
)
def start_watch(
    mailbox_id: int,
    db: Session = Depends(get_db),
):
    """Start or renew push notification watch for a mailbox."""
    mailbox = mailbox_service.get_mailbox(db=db, mailbox_id=mailbox_id)
    if not mailbox:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Mailbox not found.",
        )
    if mailbox.provider.lower() == "gmail":
        from backend.app.services.gmail.watcher import start_mailbox_watch
        return start_mailbox_watch(db=db, mailbox=mailbox)
    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail=f"Watch is not supported for provider '{mailbox.provider}'.",
    )


@router.get(
    "/{mailbox_id}/messages",
    status_code=status.HTTP_200_OK,
    summary="List recent messages from connected mailbox",
)
def list_mailbox_messages(
    mailbox_id: int,
    max_results: int = Query(30, ge=1, le=100, description="Max messages to fetch"),
    q: Optional[str] = Query(None, description="Optional search query"),
    response: Response = None,
    db: Session = Depends(get_db),
) -> List[Dict[str, Any]]:
    """Fetch recent messages directly from provider API in memory (zero disk/eml)."""
    if response is not None:
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    mailbox = mailbox_service.get_mailbox(db=db, mailbox_id=mailbox_id)
    if not mailbox:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Mailbox not found.",
        )
    if mailbox.provider.lower() == "gmail":
        from backend.app.services.gmail.client import build_gmail_service, list_gmail_messages
        from backend.app.services.gmail.token_store import TokenStore

        creds = TokenStore.get_credentials(db=db, mailbox=mailbox)
        if not creds:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Mailbox has no active Google OAuth credentials. Please authenticate via OAuth.",
            )
        service = build_gmail_service(credentials=creds)
        return list_gmail_messages(service=service, max_results=max_results, query=q)

    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail=f"Message listing not supported for provider '{mailbox.provider}'.",
    )


@router.post(
    "/{mailbox_id}/messages/{message_id}/analyze",
    status_code=status.HTTP_200_OK,
    summary="Fetch and analyze a specific message directly from mailbox in memory",
)
def analyze_mailbox_message(
    mailbox_id: int,
    message_id: str,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Retrieve message from provider in memory, parse it, run analysis pipeline, and return result.

    Zero .eml or disk download required.
    """
    mailbox = mailbox_service.get_mailbox(db=db, mailbox_id=mailbox_id)
    if not mailbox:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Mailbox not found.",
        )
    if mailbox.provider.lower() == "gmail":
        from backend.app.services.gmail.client import GmailProviderClient
        from backend.app.services.analysis_pipeline import default_pipeline

        provider_client = GmailProviderClient(db_session=db)
        normalized_email = provider_client.fetch_message(
            provider_message_id=message_id,
            account_email=mailbox.account_email,
        )
        case, stage_results = default_pipeline.run(
            db=db,
            email=normalized_email,
        )
        # Link corresponding SecurityAlert if exists
        alert = (
            db.query(SecurityAlert)
            .filter(SecurityAlert.mailbox_id == mailbox.id, SecurityAlert.message_id == message_id)
            .first()
        )
        if alert:
            alert.case_id = case.id
            alert.status = AlertStatus.INVESTIGATING.value
            alert.updated_at = datetime.now(timezone.utc)
            db.commit()
            db.refresh(alert)

        return {
            "alert_id": alert.alert_id if alert else None,
            "case": {
                "id": case.id,
                "case_id": case.case_id,
                "status": case.status,
                "classification": case.classification,
                "ai_confidence": case.ai_confidence,
                "risk_score": case.risk_score,
                "created_at": case.created_at.isoformat() if case.created_at else None,
            },
            "analysis": {
                "classification": case.classification,
                "ai_confidence": case.ai_confidence,
                "risk_score": case.risk_score,
                "forensics": stage_results.get("forensics", {}),
                "authentication": stage_results.get("authentication", {}),
                "ml": stage_results.get("ml", {}),
                "intelligence": stage_results.get("intelligence", {}),
                "correlation": stage_results.get("correlation", {}),
                "risk": stage_results.get("risk", {}),
            },
        }


    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail=f"Message analysis not supported for provider '{mailbox.provider}'.",
    )


@router.post(
    "/{mailbox_id}/messages/{message_id}/pre-scan",
    response_model=PreOpenScanResponse,
    status_code=status.HTTP_200_OK,
    summary="Fast in-memory pre-open threat scan for an email before opening",
)
def pre_open_scan_mailbox_message(
    mailbox_id: int,
    message_id: str,
    db: Session = Depends(get_db),
) -> PreOpenScanResponse:
    """Retrieve message in memory and execute fast pre-open threat evaluation.

    Returns immediate security preview, explainable reasons, and recommended actions
    prior to opening the email, with zero raw content persisted to disk.
    """
    mailbox = mailbox_service.get_mailbox(db=db, mailbox_id=mailbox_id)
    if not mailbox:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Mailbox not found.",
        )

    if mailbox.provider.lower() == "gmail":
        from backend.app.services.gmail.client import GmailProviderClient
        from backend.app.services.pre_open_scan import scan_email_pre_open

        provider_client = GmailProviderClient(db_session=db)
        normalized_email = provider_client.fetch_message(
            provider_message_id=message_id,
            account_email=mailbox.account_email,
        )
        return scan_email_pre_open(email=normalized_email)

    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail=f"Pre-open scan not supported for provider '{mailbox.provider}'.",
    )


@router.post(
    "/{mailbox_id}/messages/{message_id}/report-spam",
    response_model=ReportSpamResponse,
    status_code=status.HTTP_200_OK,
    summary="Report message as spam via Gmail API",
)
def report_spam_mailbox_message(
    mailbox_id: int,
    message_id: str,
    db: Session = Depends(get_db),
) -> ReportSpamResponse:
    """Classify and report email as spam in connected Gmail mailbox."""
    mailbox = mailbox_service.get_mailbox(db=db, mailbox_id=mailbox_id)
    if not mailbox:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Mailbox not found.",
        )

    if mailbox.provider.lower() == "gmail":
        from backend.app.services.gmail.client import GmailProviderClient

        provider_client = GmailProviderClient(db_session=db)
        result = provider_client.report_spam(
            provider_message_id=message_id,
            account_email=mailbox.account_email,
        )
        logger.info(
            "Gmail remediation REPORT_SPAM executed: mailbox_id=%s, message_id=%s, provider=%s, status=%s",
            mailbox_id,
            message_id,
            mailbox.provider,
            result.get("status"),
        )
        try:
            from backend.app.services.event_broadcaster import broadcast_mailbox_event

            broadcast_mailbox_event(
                mailbox_id=mailbox.id,
                event_type="MESSAGE_REMEDIATED",
                payload={"action": "REPORT_SPAM", "message_id": message_id},
            )
        except Exception:
            pass
        return ReportSpamResponse(
            success=result.get("success", True),
            action=result.get("action", "REPORT_SPAM"),
            message_id=message_id,
            status=result.get("status", "REPORTED"),
        )

    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail=f"Report spam not supported for provider '{mailbox.provider}'.",
    )


@router.post(
    "/{mailbox_id}/messages/{message_id}/delete",
    response_model=TrashMessageResponse,
    status_code=status.HTTP_200_OK,
    summary="Move message to Gmail Trash",
)
def delete_mailbox_message(
    mailbox_id: int,
    message_id: str,
    db: Session = Depends(get_db),
) -> TrashMessageResponse:
    """Safely move message to Gmail Trash (reversible deletion)."""
    mailbox = mailbox_service.get_mailbox(db=db, mailbox_id=mailbox_id)
    if not mailbox:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Mailbox not found.",
        )

    if mailbox.provider.lower() == "gmail":
        from backend.app.services.gmail.client import GmailProviderClient

        provider_client = GmailProviderClient(db_session=db)
        result = provider_client.trash_message(
            provider_message_id=message_id,
            account_email=mailbox.account_email,
        )
        logger.info(
            "Gmail remediation DELETE executed: mailbox_id=%s, message_id=%s, provider=%s, status=%s",
            mailbox_id,
            message_id,
            mailbox.provider,
            result.get("status"),
        )
        try:
            from backend.app.services.event_broadcaster import broadcast_mailbox_event

            broadcast_mailbox_event(
                mailbox_id=mailbox.id,
                event_type="MESSAGE_REMEDIATED",
                payload={"action": "DELETE", "message_id": message_id},
            )
        except Exception:
            pass
        return TrashMessageResponse(
            success=result.get("success", True),
            action=result.get("action", "DELETE"),
            message_id=message_id,
            status=result.get("status", "TRASHED"),
        )

    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail=f"Delete action not supported for provider '{mailbox.provider}'.",
    )


@router.post(
    "/{mailbox_id}/messages/{message_id}/block-sender",
    response_model=BlockSenderResponse,
    status_code=status.HTTP_200_OK,
    summary="Block sender via Gmail filter",
)
def block_sender_mailbox_message(
    mailbox_id: int,
    message_id: str,
    db: Session = Depends(get_db),
) -> BlockSenderResponse:
    """Create a Gmail filter routing future messages from sender to trash."""
    mailbox = mailbox_service.get_mailbox(db=db, mailbox_id=mailbox_id)
    if not mailbox:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Mailbox not found.",
        )

    if mailbox.provider.lower() == "gmail":
        from backend.app.services.gmail.client import GmailProviderClient

        provider_client = GmailProviderClient(db_session=db)
        result = provider_client.block_sender(
            provider_message_id=message_id,
            account_email=mailbox.account_email,
        )
        logger.info(
            "Gmail remediation BLOCK_SENDER executed: mailbox_id=%s, message_id=%s, provider=%s, sender=%s, filter_id=%s, already_blocked=%s",
            mailbox_id,
            message_id,
            mailbox.provider,
            result.get("sender"),
            result.get("filter_id"),
            result.get("already_blocked"),
        )
        try:
            from backend.app.services.event_broadcaster import broadcast_mailbox_event

            broadcast_mailbox_event(
                mailbox_id=mailbox.id,
                event_type="MESSAGE_REMEDIATED",
                payload={
                    "action": "BLOCK_SENDER",
                    "message_id": message_id,
                    "sender": result.get("sender"),
                },
            )
        except Exception:
            pass
        return BlockSenderResponse(
            success=result.get("success", True),
            action=result.get("action", "BLOCK_SENDER"),
            sender=result.get("sender", ""),
            filter_id=result.get("filter_id"),
            already_blocked=result.get("already_blocked", False),
        )

    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail=f"Block sender not supported for provider '{mailbox.provider}'.",
    )


@router.get(
    "/{mailbox_id}/alerts",
    response_model=List[SecurityAlertRead],
    status_code=status.HTTP_200_OK,
    summary="List security threat alerts for a mailbox",
)
def list_mailbox_alerts(
    mailbox_id: int,
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by AlertStatus (UNREAD, READ, DISMISSED, INVESTIGATING, RESOLVED)"),
    limit: int = Query(50, ge=1, le=200, description="Max alerts to return"),
    db: Session = Depends(get_db),
) -> List[SecurityAlertRead]:
    """Retrieve normalized threat alerts for a monitored mailbox, ordered by most recent."""
    mailbox = mailbox_service.get_mailbox(db=db, mailbox_id=mailbox_id)
    if not mailbox:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Mailbox not found.",
        )

    query = db.query(SecurityAlert).filter(SecurityAlert.mailbox_id == mailbox.id)
    if status_filter:
        query = query.filter(SecurityAlert.status == status_filter.upper())

    alerts = query.order_by(SecurityAlert.created_at.desc()).limit(limit).all()
    return alerts


@router.post(
    "/{mailbox_id}/alerts/{alert_id}/read",
    response_model=SecurityAlertRead,
    status_code=status.HTTP_200_OK,
    summary="Mark a security threat alert as read",
)
def mark_alert_read(
    mailbox_id: int,
    alert_id: str,
    db: Session = Depends(get_db),
) -> SecurityAlertRead:
    """Mark alert status as READ."""
    mailbox = mailbox_service.get_mailbox(db=db, mailbox_id=mailbox_id)
    if not mailbox:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Mailbox not found.",
        )

    alert = (
        db.query(SecurityAlert)
        .filter(SecurityAlert.mailbox_id == mailbox.id, SecurityAlert.alert_id == alert_id)
        .first()
    )
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert not found.",
        )

    alert.status = AlertStatus.READ.value
    alert.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(alert)
    return alert


@router.post(
    "/{mailbox_id}/alerts/{alert_id}/dismiss",
    response_model=SecurityAlertRead,
    status_code=status.HTTP_200_OK,
    summary="Dismiss a security threat alert",
)
def dismiss_alert(
    mailbox_id: int,
    alert_id: str,
    db: Session = Depends(get_db),
) -> SecurityAlertRead:
    """Mark alert status as DISMISSED."""
    mailbox = mailbox_service.get_mailbox(db=db, mailbox_id=mailbox_id)
    if not mailbox:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Mailbox not found.",
        )

    alert = (
        db.query(SecurityAlert)
        .filter(SecurityAlert.mailbox_id == mailbox.id, SecurityAlert.alert_id == alert_id)
        .first()
    )
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert not found.",
        )

    alert.status = AlertStatus.DISMISSED.value
    alert.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(alert)
    return alert


@router.post(
    "/{mailbox_id}/sync",
    status_code=status.HTTP_200_OK,
    summary="Trigger on-demand synchronization and pre-open threat scanning for mailbox",
)
def sync_mailbox_messages(
    mailbox_id: int,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Trigger history-based synchronization and fast in-memory threat scanning."""
    mailbox = mailbox_service.get_mailbox(db=db, mailbox_id=mailbox_id)
    if not mailbox:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Mailbox not found.",
        )

    if mailbox.provider.lower() == "gmail":
        from backend.app.services.gmail.sync_service import sync_gmail_mailbox

        result = sync_gmail_mailbox(
            account_email=mailbox.account_email,
            db_session=db,
        )
        return result

    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail=f"Sync not supported for provider '{mailbox.provider}'.",
    )


@router.get(
    "/{mailbox_id}/events",
    summary="Real-time Server-Sent Events (SSE) stream for mailbox threat alerts",
)
async def mailbox_events_stream(
    mailbox_id: int,
    db: Session = Depends(get_db),
) -> StreamingResponse:
    """Subscribe to near-instantaneous (<200ms) threat alerts and remediation events."""
    mailbox = mailbox_service.get_mailbox(db=db, mailbox_id=mailbox_id)
    if not mailbox:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Mailbox not found.",
        )

    from backend.app.services.event_broadcaster import get_event_broadcaster

    broadcaster = get_event_broadcaster()
    return StreamingResponse(
        broadcaster.subscribe(mailbox_id=mailbox_id),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
