"""Authenticated Gmail API client and MailProviderClient connector implementation."""

from typing import Any, Dict, Optional
from googleapiclient.discovery import Resource, build
from googleapiclient.errors import HttpError
from google.oauth2.credentials import Credentials
from sqlalchemy.orm import Session

from backend.app.core.exceptions import MailTraceException, ResourceNotFoundError
from backend.app.core.logging import logger
from backend.app.db.session import SessionLocal
from backend.app.models.mailbox import Mailbox
from backend.app.schemas.analysis import NormalizedEmail
from backend.app.services.gmail.message_parser import parse_gmail_message
from backend.app.services.gmail.token_store import TokenStore
from backend.app.services.mail_event_service import get_mailbox_by_email
from backend.app.services.provider_client import MailProviderClient


def build_gmail_service(credentials: Credentials) -> Resource:
    """Build an authenticated Gmail API v1 service Resource."""
    return build("gmail", "v1", credentials=credentials, cache_discovery=False)


def get_user_profile(service: Resource) -> Dict[str, Any]:
    """Retrieve the primary email address and account profile from Gmail API."""
    try:
        profile = service.users().getProfile(userId="me").execute()
        return profile
    except HttpError as exc:
        logger.error("Failed to retrieve Gmail user profile: %s", str(exc))
        raise MailTraceException(
            message=f"Gmail API profile error: {exc.reason}",
            code="GMAIL_API_ERROR",
            status_code=exc.status_code if hasattr(exc, "status_code") else 502,
        ) from exc


def fetch_gmail_message_resource(service: Resource, message_id: str) -> Dict[str, Any]:
    """Fetch full structured message JSON for a given message ID."""
    try:
        msg = service.users().messages().get(
            userId="me",
            id=message_id,
            format="full",
        ).execute()
        return msg
    except HttpError as exc:
        if exc.status_code == 404:
            logger.warning("Gmail message '%s' not found on provider", message_id)
            raise ResourceNotFoundError(
                message=f"Gmail message '{message_id}' not found.",
                code="GMAIL_MESSAGE_NOT_FOUND",
            ) from exc
        logger.error("Gmail API error fetching message '%s': %s", message_id, str(exc))
        raise MailTraceException(
            message=f"Gmail API error: {exc.reason}",
            code="GMAIL_API_ERROR",
            status_code=exc.status_code if hasattr(exc, "status_code") else 502,
        ) from exc


def list_gmail_messages(
    service: Resource,
    max_results: int = 30,
    query: Optional[str] = None,
) -> list[Dict[str, Any]]:
    """List recent messages from Gmail inbox with snippet and basic headers.

    Zero local file download. Operates entirely in memory via Gmail API.
    """
    try:
        kwargs: Dict[str, Any] = {"userId": "me", "maxResults": max_results}
        if query:
            kwargs["q"] = query
        result = service.users().messages().list(**kwargs).execute()
        messages_meta = result.get("messages", [])
        detailed_list: list[Dict[str, Any]] = []
        for meta in messages_meta:
            m_id = meta["id"]
            try:
                msg_data = service.users().messages().get(
                    userId="me",
                    id=m_id,
                    format="metadata",
                    metadataHeaders=["From", "Subject", "Date", "To"],
                ).execute()
                headers = {
                    h.get("name", ""): h.get("value", "")
                    for h in msg_data.get("payload", {}).get("headers", [])
                }
                raw_subj = headers.get("Subject", "")
                subj_clean = raw_subj.strip() if (raw_subj and raw_subj.strip()) else "(No Subject)"
                detailed_list.append({
                    "id": m_id,
                    "thread_id": msg_data.get("threadId"),
                    "snippet": msg_data.get("snippet", ""),
                    "from": headers.get("From", ""),
                    "to": headers.get("To", ""),
                    "subject": subj_clean,
                    "date": headers.get("Date", ""),
                })
            except Exception as e:
                logger.warning("Failed to fetch message metadata for %s: %s", m_id, e)
                detailed_list.append({"id": m_id, "snippet": "", "subject": "(No Subject)"})
        return detailed_list
    except HttpError as exc:
        logger.error("Failed to list Gmail messages: %s", str(exc))
        raise MailTraceException(
            message=f"Gmail API list error: {exc.reason}",
            code="GMAIL_API_ERROR",
            status_code=exc.status_code if hasattr(exc, "status_code") else 502,
        ) from exc


class GmailProviderClient(MailProviderClient):
    """Concrete MailProviderClient connector for Google Gmail."""

    def __init__(self, db_session: Optional[Session] = None) -> None:
        self._db_session = db_session

    def _get_db(self) -> Session:
        return self._db_session if self._db_session is not None else SessionLocal()

    def fetch_message(
        self,
        provider_message_id: str,
        account_email: Optional[str] = None,
    ) -> NormalizedEmail:
        """Fetch message from Gmail API in memory and return NormalizedEmail without disk writes.

        Args:
            provider_message_id: Gmail message identifier.
            account_email: Connected account email to retrieve OAuth credentials for.

        Returns:
            In-memory NormalizedEmail instance.
        """
        if not account_email:
            raise ValueError("account_email is required to retrieve credentials for GmailProviderClient.")

        should_close_db = self._db_session is None
        db = self._get_db()
        try:
            mailbox = get_mailbox_by_email(db=db, account_email=account_email)
            if not mailbox:
                raise ResourceNotFoundError(f"Mailbox for account '{account_email}' does not exist.")

            creds = TokenStore.get_credentials(db=db, mailbox=mailbox)
            if not creds:
                raise MailTraceException(
                    message=f"No active credentials for mailbox '{account_email}'. Please authenticate via Google OAuth.",
                    code="GMAIL_CREDENTIALS_MISSING",
                    status_code=401,
                )

            service = build_gmail_service(credentials=creds)
            msg_resource = fetch_gmail_message_resource(service=service, message_id=provider_message_id)
            return parse_gmail_message(message_resource=msg_resource, mailbox_id=mailbox.id)
        finally:
            if should_close_db:
                db.close()
