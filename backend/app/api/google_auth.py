"""API router for Google OAuth 2.0 authentication and authorization callback."""

from typing import Any, Dict, Optional, Union
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
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
    response_model=None,
    status_code=status.HTTP_200_OK,
    summary="Generate Google OAuth authorization URL or redirect to consent",
)
def google_oauth_login(
    request: Request,
    redirect_uri: Optional[str] = Query(None, description="Optional custom redirect URI override"),
    redirect: bool = Query(False, description="Whether to automatically redirect to Google consent screen"),
) -> Union[Dict[str, str], RedirectResponse]:
    """Generate a secure Google OAuth consent authorization URL with CSRF protection."""
    auth_url, state = build_authorization_url(redirect_uri=redirect_uri)
    accept_header = request.headers.get("accept", "")
    # Automatically redirect browsers navigating directly to this URL
    if redirect or ("text/html" in accept_header and "application/json" not in accept_header):
        return RedirectResponse(url=auth_url, status_code=status.HTTP_307_TEMPORARY_REDIRECT)

    return {
        "authorization_url": auth_url,
        "state": state,
    }


@router.get(
    "/callback",
    response_model=None,
    status_code=status.HTTP_200_OK,
    summary="Handle Google OAuth callback",
)
def google_oauth_callback(
    request: Request,
    code: Optional[str] = Query(None, description="Google OAuth authorization code"),
    state: Optional[str] = Query(None, description="CSRF state parameter"),
    redirect_uri: Optional[str] = Query(None, description="Redirect URI matching authorization request"),
    error: Optional[str] = Query(None, description="Error returned by Google OAuth consent"),
    format: Optional[str] = Query(None, description="Optional response format (json or html)"),
    db: Session = Depends(get_db),
) -> Union[Dict[str, Any], HTMLResponse]:
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

    # 5. Deep link URL for returning to the Android app
    deep_link_url = f"mailtrace://oauth?status=connected&mailbox_id={mailbox.id}"

    # Explicit HTTP redirect requested
    if format == "redirect":
        return RedirectResponse(url=deep_link_url, status_code=status.HTTP_307_TEMPORARY_REDIRECT)

    # Check if caller prefers HTML/Browser navigation (Google OAuth redirect via mobile/desktop browser)
    accept_header = request.headers.get("accept", "")
    if format == "html" or ("text/html" in accept_header and "application/json" not in accept_header):
        expo_url = f"exp://172.22.214.63:8081/--/oauth?status=connected&mailbox_id={mailbox.id}"
        intent_url = f"intent://172.22.214.63:8081/--/oauth?status=connected&mailbox_id={mailbox.id}#Intent;scheme=exp;package=host.exp.exponent;end"

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MailTrace AI — Gmail Connected</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            background: #090d16;
            color: #f1f5f9;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            padding: 24px;
        }}
        .card {{
            background: #111827;
            border: 1px solid #1f2937;
            border-radius: 16px;
            padding: 36px 28px;
            max-width: 440px;
            width: 100%;
            text-align: center;
            box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.5), 0 8px 10px -6px rgba(0, 0, 0, 0.5);
        }}
        .badge {{
            width: 64px;
            height: 64px;
            border-radius: 50%;
            background: rgba(16, 185, 129, 0.15);
            border: 2px solid #10b981;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            font-size: 32px;
            color: #10b981;
            margin-bottom: 20px;
        }}
        h1 {{ font-size: 22px; font-weight: 700; margin-bottom: 10px; color: #ffffff; }}
        p {{ color: #94a3b8; font-size: 14px; line-height: 1.6; margin-bottom: 20px; }}
        .email-box {{
            background: #1e293b;
            border: 1px solid #334155;
            padding: 10px 14px;
            border-radius: 8px;
            color: #38bdf8;
            font-size: 14px;
            font-weight: 600;
            word-break: break-all;
            margin-bottom: 24px;
        }}
        .btn {{
            display: block;
            width: 100%;
            padding: 14px;
            background: #2563eb;
            color: #ffffff;
            font-weight: 600;
            text-decoration: none;
            border-radius: 10px;
            transition: background 0.2s;
            font-size: 15px;
            cursor: pointer;
        }}
        .btn:hover {{ background: #1d4ed8; }}
        .hint {{ font-size: 13px; color: #94a3b8; margin-top: 18px; line-height: 1.5; }}
    </style>
</head>
<body>
    <div class="card">
        <div class="badge">✓</div>
        <h1>Gmail Account Connected</h1>
        <p>MailTrace AI has successfully authenticated and linked your mailbox.</p>
        <div class="email-box">{mailbox.account_email}</div>
        <a class="btn" id="return-btn" href="{expo_url}" onclick="openApp(event)">Return to MailTrace App</a>
        <div class="hint">Mailbox linked! Simply switch back to your open MailTrace app on your phone.</div>
    </div>
    <script>
        function openApp(e) {{
            if (e) e.preventDefault();
            window.location.href = "{intent_url}";
            setTimeout(function() {{ window.location.href = "{expo_url}"; }}, 200);
            setTimeout(function() {{ window.location.href = "{deep_link_url}"; }}, 500);
        }}
        // Automatic redirection attempt
        setTimeout(function() {{ openApp(); }}, 100);
    </script>
</body>
</html>"""
        return HTMLResponse(
            content=html_content,
            status_code=status.HTTP_200_OK,
            headers={"Location": deep_link_url},
        )

    # 6. Return JSON response for automated test suites and API clients
    return {
        "status": "connected",
        "provider": "gmail",
        "account_email": mailbox.account_email,
        "mailbox_id": mailbox.id,
        "redirect_url": deep_link_url,
    }
