"""Google OAuth 2.0 flow, CSRF state protection, and authorization code exchange."""

import secrets
import time
from typing import Dict, Optional, Tuple
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials

from backend.app.core.config import settings
from backend.app.core.exceptions import MailTraceException
from backend.app.core.logging import logger

# In-memory OAuth state registry: state_token -> expiration_timestamp
# States have a 10-minute validity window and are single-use
_oauth_states: Dict[str, float] = {}
OAUTH_STATE_TTL_SECONDS = 600


class OAuthStateError(MailTraceException):
    """Exception raised when OAuth state validation fails."""

    def __init__(self, message: str = "Invalid or expired OAuth state", code: str = "INVALID_OAUTH_STATE", status_code: int = 400) -> None:
        super().__init__(message=message, code=code, status_code=status_code)


def _cleanup_expired_states() -> None:
    """Purge expired state tokens from the in-memory cache."""
    current_time = time.time()
    expired_keys = [k for k, exp in _oauth_states.items() if exp < current_time]
    for k in expired_keys:
        _oauth_states.pop(k, None)


def generate_oauth_state() -> str:
    """Generate and record a single-use cryptographically secure random state token."""
    _cleanup_expired_states()
    state = secrets.token_urlsafe(32)
    _oauth_states[state] = time.time() + OAUTH_STATE_TTL_SECONDS
    return state


def validate_and_consume_state(state: Optional[str]) -> bool:
    """Validate that the provided state is registered and not expired, then immediately consume it."""
    _cleanup_expired_states()
    if not state or state not in _oauth_states:
        logger.warning("Rejected OAuth callback with unknown state token")
        return False

    expiration = _oauth_states.pop(state)
    if time.time() > expiration:
        logger.warning("Rejected OAuth callback with expired state token")
        return False

    return True


def get_client_config() -> dict:
    """Construct Google OAuth client config dictionary from centralized settings."""
    return {
        "web": {
            "client_id": settings.google_client_id,
            "client_secret": settings.google_client_secret,
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "redirect_uris": [settings.google_redirect_uri],
        }
    }


def build_authorization_url(redirect_uri: Optional[str] = None) -> Tuple[str, str]:
    """Generate the Google OAuth consent URL and associated CSRF state parameter.

    Returns:
        Tuple of (authorization_url, state).
    """
    state = generate_oauth_state()
    target_redirect = redirect_uri or settings.google_redirect_uri

    client_config = get_client_config()
    flow = Flow.from_client_config(
        client_config=client_config,
        scopes=settings.google_oauth_scopes_list,
        redirect_uri=target_redirect,
    )

    auth_url, _ = flow.authorization_url(
        access_type="offline",
        prompt="consent",
        include_granted_scopes="true",
        state=state,
    )

    logger.info("Generated Google OAuth authorization URL with state token (redirect: %s)", target_redirect)
    return auth_url, state


def exchange_code_for_credentials(
    code: str,
    state: str,
    redirect_uri: Optional[str] = None,
) -> Credentials:
    """Validate state and exchange an authorization code for offline access credentials.

    Args:
        code: The authorization code sent by Google's callback.
        state: The CSRF state parameter returned by Google.
        redirect_uri: The redirect URI matching the initial authorization request.

    Returns:
        Credentials instance containing access and refresh tokens.

    Raises:
        OAuthStateError: If the state token is missing, invalid, or expired.
        MailTraceException: If the token exchange fails.
    """
    if not validate_and_consume_state(state):
        raise OAuthStateError("OAuth state validation failed. State may have expired or been reused.")

    target_redirect = redirect_uri or settings.google_redirect_uri
    client_config = get_client_config()

    try:
        flow = Flow.from_client_config(
            client_config=client_config,
            scopes=settings.google_oauth_scopes_list,
            redirect_uri=target_redirect,
            state=state,
        )
        flow.fetch_token(code=code)
        logger.info("Successfully exchanged Google authorization code for credentials")
        return flow.credentials
    except Exception as exc:
        logger.error("Failed to exchange authorization code for tokens: %s", str(exc), exc_info=True)
        raise MailTraceException(
            message="Failed to exchange authorization code with Google OAuth provider.",
            code="OAUTH_EXCHANGE_FAILED",
            status_code=400,
        ) from exc
