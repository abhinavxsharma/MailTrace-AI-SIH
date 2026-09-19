"""Secure OAuth token store abstraction for connected Gmail mailboxes.

Production Note:
For local development and MVP execution, token data is serialized and stored
within the local SQLite database behind this isolated TokenStore interface.
In production environments, credentials_data should be backed by a dedicated
secrets manager (e.g., AWS Secrets Manager, HashiCorp Vault, or encrypted via KMS/Fernet).
Under NO circumstances are token strings ever logged or returned to API clients.
"""

import json
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from google.auth.exceptions import RefreshError
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from sqlalchemy.orm import Session

from backend.app.core.config import settings
from backend.app.core.exceptions import MailTraceException
from backend.app.core.logging import logger
from backend.app.models.mailbox import Mailbox


class GmailAuthError(MailTraceException):
    """Exception raised when Gmail authentication or token refresh fails."""

    def __init__(self, message: str = "Gmail authentication error", code: str = "GMAIL_AUTH_ERROR", status_code: int = 401) -> None:
        super().__init__(message=message, code=code, status_code=status_code)


class TokenStore:
    """Manages secure persistence and token refresh for Gmail OAuth credentials."""

    @staticmethod
    def save_credentials(db: Session, mailbox: Mailbox, credentials: Credentials) -> None:
        """Serialize and persist OAuth credentials for a connected mailbox.

        Tokens are never logged.
        """
        token_data: Dict[str, Any] = {
            "token": credentials.token,
            "refresh_token": credentials.refresh_token,
            "token_uri": credentials.token_uri or "https://oauth2.googleapis.com/token",
            "client_id": credentials.client_id or settings.google_client_id,
            "client_secret": credentials.client_secret or settings.google_client_secret,
            "scopes": credentials.scopes or settings.google_oauth_scopes_list,
        }
        if credentials.expiry:
            token_data["expiry"] = credentials.expiry.isoformat()

        mailbox.credentials_data = json.dumps(token_data)
        mailbox.updated_at = datetime.now(timezone.utc)
        db.add(mailbox)
        db.commit()
        db.refresh(mailbox)
        logger.info("Successfully persisted credentials for mailbox ID %s (email: %s)", mailbox.id, mailbox.account_email)

    @staticmethod
    def get_credentials(db: Session, mailbox: Mailbox) -> Optional[Credentials]:
        """Load and auto-refresh credentials for a mailbox.

        Returns valid, authenticated google.oauth2.credentials.Credentials instance.
        Raises GmailAuthError if credentials are missing, expired without refresh token,
        or revoked by Google.
        """
        if not mailbox.credentials_data:
            logger.warning("No credentials found for mailbox ID %s (%s)", mailbox.id, mailbox.account_email)
            return None

        try:
            data = json.loads(mailbox.credentials_data)
        except (ValueError, TypeError) as exc:
            logger.error("Corrupted credential JSON for mailbox ID %s: %s", mailbox.id, str(exc))
            raise GmailAuthError("Corrupted mailbox credentials stored in database.") from exc

        expiry = None
        if "expiry" in data and data["expiry"]:
            try:
                expiry = datetime.fromisoformat(data["expiry"])
            except ValueError:
                expiry = None

        creds = Credentials(
            token=data.get("token"),
            refresh_token=data.get("refresh_token"),
            token_uri=data.get("token_uri", "https://oauth2.googleapis.com/token"),
            client_id=data.get("client_id") or settings.google_client_id,
            client_secret=data.get("client_secret") or settings.google_client_secret,
            scopes=data.get("scopes") or settings.google_oauth_scopes_list,
            expiry=expiry,
        )

        # Handle automatic token refresh if expired or near expiration
        if creds.expired and creds.refresh_token:
            logger.info("Access token expired for mailbox ID %s. Performing token refresh...", mailbox.id)
            try:
                creds.refresh(Request())
                TokenStore.save_credentials(db=db, mailbox=mailbox, credentials=creds)
                logger.info("Access token successfully refreshed and saved for mailbox ID %s", mailbox.id)
            except RefreshError as ref_err:
                logger.error("Token refresh failed (revoked or expired grant) for mailbox ID %s: %s", mailbox.id, str(ref_err))
                raise GmailAuthError(
                    message="Gmail authorization has expired or been revoked. Please re-authenticate.",
                    code="GMAIL_TOKEN_REVOKED",
                    status_code=401,
                ) from ref_err
            except Exception as exc:
                logger.error("Unexpected error refreshing token for mailbox ID %s: %s", mailbox.id, str(exc))
                raise GmailAuthError("Failed to refresh Gmail access token.") from exc

        return creds

    @staticmethod
    def clear_credentials(db: Session, mailbox: Mailbox) -> None:
        """Remove stored credentials upon disconnect or revocation."""
        mailbox.credentials_data = None
        mailbox.updated_at = datetime.now(timezone.utc)
        db.add(mailbox)
        db.commit()
        db.refresh(mailbox)
        logger.info("Cleared credentials for mailbox ID %s", mailbox.id)
