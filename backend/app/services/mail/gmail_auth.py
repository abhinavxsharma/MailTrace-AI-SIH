"""
MAILTRACE AI — Gmail OAuth 2.0 authentication.

Provides ``get_credentials()``, the single entry point for obtaining a
valid ``google.oauth2.credentials.Credentials`` object for the Gmail API.

SCOPE
-----
Only the read-only Gmail scope is requested:
    https://www.googleapis.com/auth/gmail.readonly

No send, delete, modify, or compose permissions are granted or requested.

CREDENTIAL HANDLING
-------------------
- OAuth client secrets are read from the path specified by
  ``settings.GOOGLE_OAUTH_CLIENT_SECRETS_FILE``.
- The dev token cache is stored at ``settings.GOOGLE_OAUTH_TOKEN_FILE``.
- Both paths MUST be gitignored.  See project .gitignore.
- No credentials, secrets, or tokens are ever hardcoded in this file.

DEVELOPMENT vs PRODUCTION
--------------------------
Development:
    The ``InstalledAppFlow`` is used.  On first run it opens a browser to
    complete the OAuth consent flow and writes a token.json to the path
    configured in settings.  Subsequent calls use the cached (and
    auto-refreshed) token.

Production (NOT implemented in this chunk — stub comment only):
    Replace ``InstalledAppFlow`` with ``google.oauth2.service_account``
    credentials and domain-wide delegation.  The token file is not needed.

IMPORT SAFETY
-------------
Importing this module never crashes, even when credentials are missing.
Only calling ``get_credentials()`` raises ``GmailAuthError`` on misconfiguration.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import TYPE_CHECKING

from app.core.logging import get_logger

if TYPE_CHECKING:
    from google.oauth2.credentials import Credentials

logger = get_logger(__name__)

# --------------------------------------------------------------------------- #
# Constants                                                                    #
# --------------------------------------------------------------------------- #

GMAIL_READONLY_SCOPE = "https://www.googleapis.com/auth/gmail.readonly"
GMAIL_SCOPES: list[str] = [GMAIL_READONLY_SCOPE]


# --------------------------------------------------------------------------- #
# Custom exception                                                             #
# --------------------------------------------------------------------------- #

class GmailAuthError(Exception):
    """
    Raised when Gmail OAuth configuration is invalid or missing.

    Attributes:
        message: Human-readable description of the error.
        detail:  Optional structured context (e.g. missing env var name).
    """

    def __init__(self, message: str, *, detail: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.detail = detail

    def __repr__(self) -> str:
        return f"GmailAuthError(message={self.message!r}, detail={self.detail!r})"


# --------------------------------------------------------------------------- #
# Public API                                                                   #
# --------------------------------------------------------------------------- #

def get_credentials(settings: object | None = None) -> "Credentials":
    """
    Obtain a valid ``google.oauth2.credentials.Credentials`` object.

    The function:
    1. Resolves credential and token file paths from *settings* (or from the
       default ``get_settings()`` singleton if *settings* is None).
    2. If a cached token exists at the token file path and is still valid,
       returns it immediately.
    3. If the token is expired, attempts to refresh it using the stored
       refresh token.
    4. If no valid token exists, initiates the ``InstalledAppFlow``
       browser-based consent flow (development only).

    Args:
        settings: Optional ``Settings`` instance.  Defaults to the
                  application singleton returned by ``get_settings()``.

    Returns:
        A valid ``google.oauth2.credentials.Credentials`` object.

    Raises:
        GmailAuthError: If the client secrets file path is not configured,
                        the file does not exist, or the OAuth flow fails.
        ImportError:    If the Google Auth libraries are not installed.
    """
    if settings is None:
        from app.core.config import get_settings
        settings = get_settings()

    secrets_path = Path(getattr(settings, "GOOGLE_OAUTH_CLIENT_SECRETS_FILE", ""))
    token_path = Path(getattr(settings, "GOOGLE_OAUTH_TOKEN_FILE", ""))

    _validate_secrets_path(secrets_path)

    creds = _load_cached_token(token_path)

    if creds and creds.valid:
        logger.info("Gmail credentials loaded from token cache.")
        return creds

    if creds and creds.expired and creds.refresh_token:
        creds = _refresh_credentials(creds)
        _save_token(creds, token_path)
        return creds

    # No valid cached token — run the OAuth flow.
    creds = _run_oauth_flow(secrets_path)
    _save_token(creds, token_path)
    return creds


# --------------------------------------------------------------------------- #
# Internal helpers                                                             #
# --------------------------------------------------------------------------- #

def _validate_secrets_path(secrets_path: Path) -> None:
    """
    Raise GmailAuthError if the client secrets file path is missing or empty.

    Does NOT check whether the file exists yet — that is deferred to the
    OAuth library, which provides clearer error messages.
    """
    raw_str = str(secrets_path).strip()
    if not raw_str or raw_str == ".":
        raise GmailAuthError(
            "GOOGLE_OAUTH_CLIENT_SECRETS_FILE is not configured.  "
            "Set this environment variable to the path of your credentials.json "
            "file downloaded from the Google Cloud Console.",
            detail="GOOGLE_OAUTH_CLIENT_SECRETS_FILE is empty or unset",
        )

    if not secrets_path.exists():
        raise GmailAuthError(
            f"Gmail client secrets file not found: {secrets_path}  "
            "Download credentials.json from the Google Cloud Console and "
            "set GOOGLE_OAUTH_CLIENT_SECRETS_FILE to its path.  "
            "Never commit this file to version control.",
            detail=f"File not found: {secrets_path}",
        )


def _load_cached_token(token_path: Path) -> "Credentials | None":
    """
    Load a previously stored OAuth token from disk.

    Returns None if the token file does not exist or cannot be parsed.
    Never raises — errors are logged and None is returned.
    """
    if not token_path.exists():
        return None

    try:
        from google.oauth2.credentials import Credentials

        creds = Credentials.from_authorized_user_file(str(token_path), GMAIL_SCOPES)
        logger.info("Loaded cached OAuth token from %s", token_path)
        return creds
    except Exception as exc:  # noqa: BLE001
        logger.warning("Could not load cached token (%s): %s", token_path, exc)
        return None


def _refresh_credentials(creds: "Credentials") -> "Credentials":
    """
    Refresh an expired credential using its stored refresh token.

    Raises:
        GmailAuthError: If the refresh fails.
    """
    try:
        import google.auth.transport.requests as _requests

        request = _requests.Request()
        creds.refresh(request)
        logger.info("Gmail OAuth token refreshed successfully.")
        return creds
    except Exception as exc:
        raise GmailAuthError(
            f"Failed to refresh Gmail OAuth token: {exc}",
            detail=str(exc),
        ) from exc


def _run_oauth_flow(secrets_path: Path) -> "Credentials":
    """
    Run the InstalledAppFlow browser-based OAuth consent.

    DEVELOPMENT USE ONLY.
    In production, replace this with service-account domain-wide delegation.

    Raises:
        GmailAuthError: If the flow cannot be completed.
    """
    try:
        from google_auth_oauthlib.flow import InstalledAppFlow

        logger.info("Starting Gmail OAuth consent flow (browser will open).")
        flow = InstalledAppFlow.from_client_secrets_file(str(secrets_path), GMAIL_SCOPES)
        creds = flow.run_local_server(port=0, open_browser=True)
        logger.info("Gmail OAuth consent flow completed successfully.")
        return creds
    except Exception as exc:
        raise GmailAuthError(
            f"Gmail OAuth flow failed: {exc}",
            detail=str(exc),
        ) from exc


def _save_token(creds: "Credentials", token_path: Path) -> None:
    """
    Persist the OAuth token to disk for future reuse.

    Creates parent directories as needed.
    Logs a warning and continues if the write fails (non-fatal).

    The token file path MUST be in a gitignored location.
    """
    try:
        token_path.parent.mkdir(parents=True, exist_ok=True)
        token_path.write_text(creds.to_json(), encoding="utf-8")
        logger.info("OAuth token saved to %s", token_path)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Could not persist OAuth token to %s: %s", token_path, exc)
