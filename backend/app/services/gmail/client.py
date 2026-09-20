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


def _handle_gmail_http_error(exc: HttpError, message_id: Optional[str] = None) -> None:
    """Normalize Google HttpError into consistent MailTraceException or ResourceNotFoundError."""
    status_code = getattr(exc, "status_code", 500)
    if not status_code and hasattr(exc, "resp"):
        status_code = getattr(exc.resp, "status", 500)
    try:
        status_code = int(status_code)
    except (ValueError, TypeError):
        status_code = 500

    error_details = ""
    try:
        if hasattr(exc, "content") and exc.content:
            error_details = exc.content.decode("utf-8") if isinstance(exc.content, bytes) else str(exc.content)
    except Exception:
        error_details = str(exc)

    if status_code == 404:
        msg = f"Gmail message '{message_id}' not found." if message_id else "Gmail resource not found."
        logger.warning(msg)
        raise ResourceNotFoundError(message=msg, code="GMAIL_MESSAGE_NOT_FOUND") from exc

    if status_code == 403:
        if (
            "insufficientPermissions" in error_details
            or "ACCESS_TOKEN_SCOPE_INSUFFICIENT" in error_details
            or "Insufficient Permission" in str(exc)
            or "insufficient" in error_details.lower()
        ):
            logger.warning("Gmail API returned 403 insufficient permissions: %s", error_details)
            raise MailTraceException(
                message="Additional Gmail permission required. Reconnect Gmail to enable security actions.",
                code="INSUFFICIENT_PERMISSIONS",
                status_code=403,
            ) from exc
        logger.warning("Gmail API returned 403 forbidden: %s", error_details)
        raise MailTraceException(
            message="Access to Gmail resource is forbidden. Please verify account permissions.",
            code="GMAIL_FORBIDDEN",
            status_code=403,
        ) from exc

    if status_code == 429:
        logger.warning("Gmail API rate limited (429)")
        raise MailTraceException(
            message="Gmail rate limit reached. Please wait and try again.",
            code="GMAIL_RATE_LIMITED",
            status_code=429,
        ) from exc

    if status_code >= 500:
        logger.error("Gmail API 5xx server error (%d): %s", status_code, str(exc))
        raise MailTraceException(
            message="Gmail is temporarily unavailable. Please try again.",
            code="GMAIL_API_ERROR",
            status_code=502,
        ) from exc

    logger.error("Gmail API unexpected error (%d): %s", status_code, str(exc))
    raise MailTraceException(
        message=f"Gmail API error: {exc.reason if hasattr(exc, 'reason') else str(exc)}",
        code="GMAIL_API_ERROR",
        status_code=status_code if 400 <= status_code < 600 else 502,
    ) from exc


def report_gmail_spam(service: Resource, message_id: str) -> Dict[str, Any]:
    """Report email message as spam by modifying labels: add SPAM, remove INBOX.

    Uses Gmail users.messages.modify endpoint. Requires gmail.modify scope.
    """
    try:
        service.users().messages().modify(
            userId="me",
            id=message_id,
            body={
                "addLabelIds": ["SPAM"],
                "removeLabelIds": ["INBOX"],
            },
        ).execute()
        return {
            "success": True,
            "action": "REPORT_SPAM",
            "message_id": message_id,
            "status": "REPORTED",
        }
    except HttpError as exc:
        _handle_gmail_http_error(exc, message_id=message_id)


def trash_gmail_message(service: Resource, message_id: str) -> Dict[str, Any]:
    """Move email message to Gmail Trash (safe reversible delete).

    Uses Gmail users.messages.trash endpoint. Requires gmail.modify scope.
    """
    try:
        service.users().messages().trash(
            userId="me",
            id=message_id,
        ).execute()
        return {
            "success": True,
            "action": "DELETE",
            "message_id": message_id,
            "status": "TRASHED",
        }
    except HttpError as exc:
        _handle_gmail_http_error(exc, message_id=message_id)


def block_gmail_sender(service: Resource, message_id: str) -> Dict[str, Any]:
    """Block future messages from sender by creating a Gmail filter.

    1. Safely fetches From header from message metadata.
    2. Extracts canonical sender email via email.utils.parseaddr.
    3. Inspects existing filters to detect if sender is already blocked (idempotent).
    4. If not blocked, creates filter with criteria 'from' matching sender and action
       removeLabelIds=['INBOX'], addLabelIds=['TRASH'].
    Requires gmail.settings.basic scope.
    """
    from email.utils import parseaddr

    try:
        # 1. Fetch message metadata for From header
        msg_data = service.users().messages().get(
            userId="me",
            id=message_id,
            format="metadata",
            metadataHeaders=["From"],
        ).execute()
        headers = msg_data.get("payload", {}).get("headers", [])
        from_raw = next(
            (h.get("value", "") for h in headers if h.get("name", "").lower() == "from"),
            "",
        )

        _, sender_email = parseaddr(from_raw)
        sender_email = sender_email.strip().lower()

        if not sender_email or "@" not in sender_email or sender_email.startswith("@") or sender_email.endswith("@"):
            raise MailTraceException(
                message="Unable to extract a valid sender email address from message to create block filter.",
                code="INVALID_SENDER_ADDRESS",
                status_code=400,
            )

        # 2. Inspect existing filters for idempotency
        existing_filters_resp = service.users().settings().filters().list(userId="me").execute()
        existing_filters = existing_filters_resp.get("filter", []) if isinstance(existing_filters_resp, dict) else []
        for filt in existing_filters:
            filt_criteria = filt.get("criteria", {}) if isinstance(filt, dict) else {}
            filt_from = filt_criteria.get("from", "").strip().lower()
            if filt_from == sender_email:
                logger.info(
                    "Sender '%s' is already blocked by Gmail filter ID '%s'",
                    sender_email,
                    filt.get("id"),
                )
                return {
                    "success": True,
                    "action": "BLOCK_SENDER",
                    "sender": sender_email,
                    "filter_id": filt.get("id"),
                    "already_blocked": True,
                }

        # 3. Create Gmail filter
        filter_body = {
            "criteria": {
                "from": sender_email,
            },
            "action": {
                "removeLabelIds": ["INBOX"],
                "addLabelIds": ["TRASH"],
            },
        }
        created = service.users().settings().filters().create(
            userId="me",
            body=filter_body,
        ).execute()

        filter_id = created.get("id") if isinstance(created, dict) else None
        logger.info("Created Gmail filter '%s' blocking sender '%s'", filter_id, sender_email)
        return {
            "success": True,
            "action": "BLOCK_SENDER",
            "sender": sender_email,
            "filter_id": filter_id,
            "already_blocked": False,
        }
    except HttpError as exc:
        _handle_gmail_http_error(exc, message_id=message_id)


class GmailProviderClient(MailProviderClient):
    """Concrete MailProviderClient connector for Google Gmail."""

    def __init__(self, db_session: Optional[Session] = None) -> None:
        self._db_session = db_session

    def _get_db(self) -> Session:
        return self._db_session if self._db_session is not None else SessionLocal()

    def _get_service_for_account(
        self, account_email: str, required_scope: Optional[str] = None
    ) -> tuple[Resource, Mailbox, bool, Session]:
        """Authenticate and retrieve Gmail service for account, checking required scopes."""
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

            # Check if required scope is present in granted credentials
            if required_scope and creds.scopes:
                has_scope = any(
                    required_scope in s or s in ("https://mail.google.com/", "https://www.googleapis.com/auth/mail.google.com")
                    for s in creds.scopes
                )
                if not has_scope:
                    raise MailTraceException(
                        message="Additional Gmail permission required. Reconnect Gmail to enable security actions.",
                        code="INSUFFICIENT_PERMISSIONS",
                        status_code=403,
                    )

            service = build_gmail_service(credentials=creds)
            return service, mailbox, should_close_db, db
        except Exception:
            if should_close_db:
                db.close()
            raise

    def fetch_message(
        self,
        provider_message_id: str,
        account_email: Optional[str] = None,
    ) -> NormalizedEmail:
        """Fetch message from Gmail API in memory and return NormalizedEmail without disk writes."""
        service, mailbox, should_close_db, db = self._get_service_for_account(account_email=account_email)
        try:
            msg_resource = fetch_gmail_message_resource(service=service, message_id=provider_message_id)
            return parse_gmail_message(message_resource=msg_resource, mailbox_id=mailbox.id)
        finally:
            if should_close_db:
                db.close()

    def report_spam(
        self,
        provider_message_id: str,
        account_email: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Classify and report message as spam via Gmail API modify."""
        service, _, should_close_db, db = self._get_service_for_account(
            account_email=account_email,
            required_scope="https://www.googleapis.com/auth/gmail.modify",
        )
        try:
            return report_gmail_spam(service=service, message_id=provider_message_id)
        finally:
            if should_close_db:
                db.close()

    def trash_message(
        self,
        provider_message_id: str,
        account_email: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Move message to Gmail Trash via Gmail API messages.trash."""
        service, _, should_close_db, db = self._get_service_for_account(
            account_email=account_email,
            required_scope="https://www.googleapis.com/auth/gmail.modify",
        )
        try:
            return trash_gmail_message(service=service, message_id=provider_message_id)
        finally:
            if should_close_db:
                db.close()

    def block_sender(
        self,
        provider_message_id: str,
        account_email: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Block sender by creating a Gmail filter routing incoming emails to trash."""
        service, _, should_close_db, db = self._get_service_for_account(
            account_email=account_email,
            required_scope="https://www.googleapis.com/auth/gmail.settings.basic",
        )
        try:
            return block_gmail_sender(service=service, message_id=provider_message_id)
        finally:
            if should_close_db:
                db.close()
