"""API router for Google OAuth 2.0 authentication and authorization callback."""

from typing import Any, Dict, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.app.core.exceptions import MailTraceException
from backend.app.core.logging import logger
from backend.app.db.session import get_db
from backend.app.models.enums import MailboxStatus
from backend.app.models.mailbox import Mailbox
from backend.app.services.gmail.client import build_gmail_service, get_user_profile
from backend.app.services.gmail.oauth import build_authorization_url, exchange_code_for_credentials
from backend.app.services.gmail.token_store import TokenStore
from backend.app.services.mail_event_service import get_mailbox_by_email

router = APIRouter()


@router.get(
    "/login",
    status_code=status.HTTP_200_OK,
    summary="Generate Google OAuth authorization URL",
)
def google_oauth_login(
    redirect_uri: Optional[str] = Query(None, description="Optional custom redirect URI override"),
) -> Dict[str, str]:
    """Generate a secure Google OAuth consent authorization URL with CSRF protection."""
    auth_url, state = build_authorization_url(redirect_uri=redirect_uri)
    return {
        "authorization_url": auth_url,
        "state": state,
    }


@router.get(
    "/callback",
    status_code=status.HTTP_200_OK,
    summary="Handle Google OAuth callback",
)
def google_oauth_callback(
    code: Optional[str] = Query(None, description="Google OAuth authorization code"),
    state: Optional[str] = Query(None, description="CSRF state parameter"),
    redirect_uri: Optional[str] = Query(None, description="Redirect URI matching authorization request"),
    error: Optional[str] = Query(None, description="Error returned by Google OAuth consent"),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Exchange authorization code for credentials, identify Gmail account, and register Mailbox.

    Credentials and tokens are never exposed in the response.
    """
    if error:
        logger.warning("Google OAuth error received in callback: %s", error)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Google OAuth authorization denied: {error}",
        )

    if not code or not state:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing required OAuth 'code' or 'state' parameters.",
        )

    # 1. Exchange code with CSRF state verification
    try:
        credentials = exchange_code_for_credentials(code=code, state=state, redirect_uri=redirect_uri)
    except MailTraceException:
        raise
    except Exception as exc:
        logger.error("OAuth token exchange exception: %s", str(exc), exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to complete Google OAuth authentication.",
        ) from exc

    # 2. Identify Gmail account identity via profile API
    service = build_gmail_service(credentials=credentials)
    profile = get_user_profile(service=service)
    account_email = profile.get("emailAddress")

    if not account_email:
        logger.error("No email address returned in Gmail user profile")
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Could not retrieve email address from Gmail account profile.",
        )

    # 3. Register or update the Mailbox record
    mailbox = get_mailbox_by_email(db=db, account_email=account_email)
    if not mailbox:
        mailbox = Mailbox(
            provider="gmail",
            account_email=account_email,
            status=MailboxStatus.CONNECTED.value,
        )
        db.add(mailbox)
        db.flush()
        logger.info("Created new Mailbox ID %s for '%s'", mailbox.id, account_email)
    else:
        mailbox.status = MailboxStatus.CONNECTED.value
        logger.info("Reconnected existing Mailbox ID %s for '%s'", mailbox.id, account_email)

    # Record initial history ID from profile if available
    profile_history_id = profile.get("historyId")
    if profile_history_id:
        mailbox.latest_history_id = str(profile_history_id)

    # 4. Securely store OAuth credentials (isolated behind TokenStore)
    TokenStore.save_credentials(db=db, mailbox=mailbox, credentials=credentials)

    # 5. Return frontend-friendly connected response without tokens
    return {
        "status": "connected",
        "provider": "gmail",
        "account_email": mailbox.account_email,
        "mailbox_id": mailbox.id,
    }
