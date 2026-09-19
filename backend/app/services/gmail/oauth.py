"""Google OAuth 2.0 flow, CSRF state protection, and authorization code exchange."""

import ipaddress
import secrets
import time
import urllib.parse
from typing import Any, Dict, Optional, Tuple
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials

from backend.app.core.config import settings
from backend.app.core.exceptions import MailTraceException
from backend.app.core.logging import logger

# In-memory OAuth state registry: state_token -> {"expires": timestamp, "code_verifier": verifier}
# States have a 10-minute validity window and are single-use
_oauth_states: Dict[str, Any] = {}
OAUTH_STATE_TTL_SECONDS = 600


class OAuthStateError(MailTraceException):
    """Exception raised when OAuth state validation fails."""

    def __init__(self, message: str = "Invalid or expired OAuth state", code: str = "INVALID_OAUTH_STATE", status_code: int = 400) -> None:
        super().__init__(message=message, code=code, status_code=status_code)


class GoogleConfigError(MailTraceException):
    """Exception raised when required Google Cloud configuration is missing."""

    def __init__(
        self,
        message: str = "Google OAuth credentials are not configured. Please set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET in .env.",
        code: str = "GOOGLE_CONFIG_MISSING",
        status_code: int = 500,
    ) -> None:
        super().__init__(message=message, code=code, status_code=status_code)


ALLOWED_REDIRECT_URIS = {
    "http://127.0.0.1:8000/api/auth/google/callback",
    "http://localhost:8000/api/auth/google/callback",
}


def _is_permissible_redirect(uri: str) -> bool:
    """Check whether a redirect URI points to /api/auth/google/callback on a safe host.

    Allowed:
    1. The configured GOOGLE_REDIRECT_URI from settings (HTTPS tunnel or custom domain).
    2. Localhost loopback development URIs in ALLOWED_REDIRECT_URIS.
    All other arbitrary hosts, IPs, or open redirects are strictly rejected.
    """
    if not uri:
        return False
    try:
        parsed = urllib.parse.urlparse(uri)
        if parsed.path != "/api/auth/google/callback":
            return False

        # Match configured GOOGLE_REDIRECT_URI from environment
        if settings.google_redirect_uri:
            cfg_parsed = urllib.parse.urlparse(settings.google_redirect_uri)
            if (
                parsed.scheme == cfg_parsed.scheme
                and parsed.netloc == cfg_parsed.netloc
                and parsed.path == cfg_parsed.path
            ):
                return True

        # Match standard local development loopback URIs
        if uri in ALLOWED_REDIRECT_URIS:
            return True

        hostname = parsed.hostname
        if not hostname:
            return False

        if hostname in ("localhost", "127.0.0.1"):
            return True

        try:
            ip = ipaddress.ip_address(hostname)
            if ip.is_loopback:
                return True
        except (ValueError, AttributeError):
            pass

        return False
    except (ValueError, AttributeError):
        return False


def validate_redirect_uri(redirect_uri: Optional[str]) -> str:
    """Validate that the redirect URI is permissible and not an arbitrary or open redirect."""
    target = redirect_uri or settings.google_redirect_uri
    if not target or not _is_permissible_redirect(target):
        raise OAuthStateError(
            f"Invalid redirect URI '{target}'. Redirect URI must match /api/auth/google/callback on localhost or the configured GOOGLE_REDIRECT_URI."
        )
    return target


def validate_oauth_config() -> None:
    """Validate that GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET are configured."""
    if not settings.google_client_id or not settings.google_client_secret:
        raise GoogleConfigError(
            "Google OAuth credentials are not configured. Please set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET in your local .env file."
        )


def _cleanup_expired_states() -> None:
    """Purge expired state tokens from the in-memory cache."""
    current_time = time.time()
    expired_keys = []
    for k, v in _oauth_states.items():
        exp = v["expires"] if isinstance(v, dict) else v
        if exp < current_time:
            expired_keys.append(k)
    for k in expired_keys:
        _oauth_states.pop(k, None)


def record_oauth_state(state: str, code_verifier: Optional[str] = None) -> None:
    """Record an OAuth state token along with its PKCE code_verifier."""
    _cleanup_expired_states()
    _oauth_states[state] = {
        "expires": time.time() + OAUTH_STATE_TTL_SECONDS,
        "code_verifier": code_verifier,
    }


def generate_oauth_state() -> str:
    """Generate and record a single-use cryptographically secure random state token."""
    state = secrets.token_urlsafe(32)
    record_oauth_state(state)
    return state


def validate_and_consume_state(state: Optional[str]) -> bool:
    """Validate that the provided state is registered and not expired, then immediately consume it."""
    _cleanup_expired_states()
    if not state or state not in _oauth_states:
        logger.warning("Rejected OAuth callback with unknown state token")
        return False

    entry = _oauth_states.pop(state)
    exp = entry["expires"] if isinstance(entry, dict) else entry
    if time.time() > exp:
        logger.warning("Rejected OAuth callback with expired state token")
        return False

    return True


def get_client_config(redirect_uri: Optional[str] = None) -> dict:
    """Construct Google OAuth client config dictionary from centralized settings."""
    target_redirect = redirect_uri or settings.google_redirect_uri
    uris = list(ALLOWED_REDIRECT_URIS)
    if target_redirect not in uris:
        uris.append(target_redirect)

    return {
        "web": {
            "client_id": settings.google_client_id,
            "client_secret": settings.google_client_secret,
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "redirect_uris": uris,
        }
    }


def build_authorization_url(redirect_uri: Optional[str] = None) -> Tuple[str, str]:
    """Generate the Google OAuth consent URL and associated CSRF state parameter.

    Returns:
        Tuple of (authorization_url, state).
    """
    validate_oauth_config()
    target_redirect = validate_redirect_uri(redirect_uri)
    state = secrets.token_urlsafe(32)

    client_config = get_client_config(redirect_uri=target_redirect)
    flow = Flow.from_client_config(
        client_config=client_config,
        scopes=settings.google_oauth_scopes_list,
        redirect_uri=target_redirect,
    )

    auth_url, _ = flow.authorization_url(
        access_type="offline",
        prompt="select_account consent",
        include_granted_scopes="true",
        state=state,
    )

    # Save state with flow's generated PKCE code_verifier so token exchange succeeds
    code_verifier = getattr(flow, "code_verifier", None)
    record_oauth_state(state=state, code_verifier=code_verifier)

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
    _cleanup_expired_states()
    if not state or state not in _oauth_states:
        raise OAuthStateError("OAuth state validation failed. State may have expired or been reused.")

    entry = _oauth_states.pop(state)
    exp = entry["expires"] if isinstance(entry, dict) else entry
    if time.time() > exp:
        raise OAuthStateError("OAuth state validation failed. State may have expired or been reused.")

    code_verifier = entry.get("code_verifier") if isinstance(entry, dict) else None

    validate_oauth_config()
    target_redirect = validate_redirect_uri(redirect_uri)
    client_config = get_client_config(redirect_uri=target_redirect)

    try:
        flow = Flow.from_client_config(
            client_config=client_config,
            scopes=settings.google_oauth_scopes_list,
            redirect_uri=target_redirect,
            state=state,
        )
        if code_verifier:
            flow.code_verifier = code_verifier

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
