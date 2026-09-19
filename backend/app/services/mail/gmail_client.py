"""
MAILTRACE AI — Typed Gmail API client wrapper.

Provides ``GmailClient``, a thin wrapper over the ``googleapiclient``
Gmail API resource.  All interaction with the Google API is isolated here.

DESIGN PRINCIPLES
-----------------
- Google API calls are isolated from the rest of MAILTRACE.
- Authentication concerns live in ``gmail_auth.py``, not here.
- No analysis, forensic inspection, or ML inference is performed here.
- No raw email content is written to disk.
- All responses are returned as plain Python dicts (Google API native format).
  The caller (``message_fetcher.py``) is responsible for parsing/normalising.
- API errors surface as ``GmailClientError``.

USAGE
-----
    from app.services.mail.gmail_auth import get_credentials
    from app.services.mail.gmail_client import GmailClient

    creds = get_credentials()
    client = GmailClient(credentials=creds)
    profile = client.get_profile()
"""

from __future__ import annotations

from typing import Any

from app.core.logging import get_logger

logger = get_logger(__name__)

# Gmail API service identifier and version.
_GMAIL_API_SERVICE = "gmail"
_GMAIL_API_VERSION = "v1"

# Sentinel used as the authenticated user identifier in Gmail API calls.
_ME = "me"


# --------------------------------------------------------------------------- #
# Custom exception                                                             #
# --------------------------------------------------------------------------- #

class GmailClientError(Exception):
    """
    Raised when a Gmail API call fails.

    Attributes:
        message:    Human-readable description.
        status_code: HTTP status code from the Google API, if available.
    """

    def __init__(self, message: str, *, status_code: int | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code

    def __repr__(self) -> str:
        return f"GmailClientError(message={self.message!r}, status_code={self.status_code!r})"


# --------------------------------------------------------------------------- #
# GmailClient                                                                  #
# --------------------------------------------------------------------------- #

class GmailClient:
    """
    Typed wrapper over the Gmail REST API.

    Constructs a ``googleapiclient`` service object from the supplied
    credentials and exposes strongly-typed methods for the operations
    needed by the MAILTRACE Gmail connector.

    Args:
        credentials: A valid ``google.oauth2.credentials.Credentials``
                     object.  Obtain via ``gmail_auth.get_credentials()``.

    Example::

        from app.services.mail.gmail_auth import get_credentials
        from app.services.mail.gmail_client import GmailClient

        creds = get_credentials()
        client = GmailClient(credentials=creds)
        profile = client.get_profile()
        print(profile["emailAddress"])
    """

    def __init__(self, credentials: Any) -> None:
        self._credentials = credentials
        self._service: Any = self._build_service()

    # ------------------------------------------------------------------ #
    # Service construction                                                 #
    # ------------------------------------------------------------------ #

    def _build_service(self) -> Any:
        """
        Build the Google API service object.

        Raises:
            GmailClientError: If the service cannot be constructed.
        """
        try:
            from googleapiclient.discovery import build  # type: ignore[import-untyped]

            service = build(
                _GMAIL_API_SERVICE,
                _GMAIL_API_VERSION,
                credentials=self._credentials,
                # cache_discovery=False prevents stale discovery docs in tests.
                cache_discovery=False,
            )
            logger.info("Gmail API service built successfully.")
            return service
        except Exception as exc:
            raise GmailClientError(
                f"Failed to build Gmail API service: {exc}"
            ) from exc

    # ------------------------------------------------------------------ #
    # Public API methods                                                   #
    # ------------------------------------------------------------------ #

    def get_profile(self) -> dict[str, Any]:
        """
        Retrieve the authenticated user's Gmail profile.

        Returns:
            A dict with at minimum:
                ``emailAddress``  — the user's email address
                ``messagesTotal`` — total number of messages
                ``threadsTotal``  — total number of threads
                ``historyId``     — current history ID

        Raises:
            GmailClientError: On API failure.
        """
        try:
            result: dict[str, Any] = (
                self._service.users().getProfile(userId=_ME).execute()
            )
            logger.info("Retrieved Gmail profile for %s", result.get("emailAddress", "<unknown>"))
            return result
        except Exception as exc:
            raise _wrap_api_error(exc, "get_profile") from exc

    def list_recent_messages(
        self,
        *,
        max_results: int = 10,
        label_ids: list[str] | None = None,
        page_token: str | None = None,
        query: str | None = None,
    ) -> dict[str, Any]:
        """
        List messages in the authenticated user's mailbox.

        Args:
            max_results: Maximum number of messages to return (1–500).
            label_ids:   Only return messages with these label IDs applied.
                         Defaults to INBOX.
            page_token:  Page token from a previous call for pagination.
            query:       Gmail search query (same syntax as the Gmail search box).

        Returns:
            A dict with:
                ``messages``      — list of ``{id, threadId}`` dicts (may be absent
                                    if no messages match)
                ``nextPageToken`` — present if more pages exist
                ``resultSizeEstimate`` — estimated result count

        Raises:
            GmailClientError: On API failure.
        """
        params: dict[str, Any] = {
            "userId": _ME,
            "maxResults": max_results,
        }
        if label_ids:
            params["labelIds"] = label_ids
        if page_token:
            params["pageToken"] = page_token
        if query:
            params["q"] = query

        try:
            result: dict[str, Any] = self._service.users().messages().list(**params).execute()
            count = len(result.get("messages", []))
            logger.info("Listed %d messages (maxResults=%d).", count, max_results)
            return result
        except Exception as exc:
            raise _wrap_api_error(exc, "list_recent_messages") from exc

    def get_message(
        self,
        message_id: str,
        *,
        fmt: str = "full",
    ) -> dict[str, Any]:
        """
        Fetch a single Gmail message by ID.

        PRIVACY: The returned dict is the raw Gmail API response, held
        entirely in memory.  This method never writes anything to disk.

        Args:
            message_id: The Gmail message ID (opaque string).
            fmt:        The format to retrieve.  One of:
                        ``"full"``     — headers + body (default, used for forensics)
                        ``"metadata"`` — headers only
                        ``"minimal"``  — minimal metadata, no body
                        ``"raw"``      — base64url-encoded raw RFC 2822 message
                                         (NOT used by MAILTRACE — raw MIME is
                                          never fetched or stored on disk)

        Returns:
            The Gmail API message resource dict.

        Raises:
            GmailClientError: On API failure or invalid message ID.
        """
        if fmt == "raw":
            # Explicitly documented: MAILTRACE never fetches raw MIME.
            # This guard prevents accidental raw MIME retrieval.
            raise GmailClientError(
                "Format 'raw' is not permitted in MAILTRACE.  "
                "Raw MIME is never fetched or stored.  Use 'full' instead.",
                status_code=None,
            )

        try:
            result: dict[str, Any] = (
                self._service.users()
                .messages()
                .get(userId=_ME, id=message_id, format=fmt)
                .execute()
            )
            logger.info(
                "Fetched message id=%s (format=%s, size_estimate=%s bytes).",
                message_id,
                fmt,
                result.get("sizeEstimate", "?"),
            )
            return result
        except Exception as exc:
            raise _wrap_api_error(exc, f"get_message(id={message_id!r})") from exc

    def get_thread(self, thread_id: str) -> dict[str, Any]:
        """
        Fetch a Gmail thread by ID.

        Returns the thread resource including all messages in the thread.
        Useful for correlating reply chains during forensic analysis.

        Args:
            thread_id: The Gmail thread ID.

        Returns:
            The Gmail API thread resource dict.

        Raises:
            GmailClientError: On API failure.
        """
        try:
            result: dict[str, Any] = (
                self._service.users()
                .threads()
                .get(userId=_ME, id=thread_id)
                .execute()
            )
            message_count = len(result.get("messages", []))
            logger.info(
                "Fetched thread id=%s (%d messages).", thread_id, message_count
            )
            return result
        except Exception as exc:
            raise _wrap_api_error(exc, f"get_thread(id={thread_id!r})") from exc


# --------------------------------------------------------------------------- #
# Internal helpers                                                             #
# --------------------------------------------------------------------------- #

def _wrap_api_error(exc: Exception, operation: str) -> GmailClientError:
    """
    Convert a ``googleapiclient.errors.HttpError`` (or any other exception)
    into a ``GmailClientError`` with a descriptive message.
    """
    try:
        # googleapiclient.errors.HttpError has a .resp attribute.
        status_code: int | None = int(exc.resp.status)  # type: ignore[union-attr]
    except (AttributeError, TypeError, ValueError):
        status_code = None

    message = f"Gmail API error in {operation}: {exc}"
    logger.error(message)
    return GmailClientError(message, status_code=status_code)
