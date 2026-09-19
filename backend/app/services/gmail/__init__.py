"""Gmail integration service module."""

from backend.app.services.gmail.client import (
    GmailProviderClient,
    build_gmail_service,
    fetch_gmail_message_resource,
    get_user_profile,
)
from backend.app.services.gmail.history import list_new_messages_from_history
from backend.app.services.gmail.message_parser import parse_gmail_message
from backend.app.services.gmail.oauth import (
    ALLOWED_REDIRECT_URIS,
    GoogleConfigError,
    build_authorization_url,
    exchange_code_for_credentials,
    generate_oauth_state,
    validate_and_consume_state,
    validate_redirect_uri,
)
from backend.app.services.gmail.sync_service import sync_gmail_mailbox
from backend.app.services.gmail.token_store import GmailAuthError, TokenStore
from backend.app.services.gmail.watcher import start_mailbox_watch, stop_mailbox_watch

__all__ = [
    "ALLOWED_REDIRECT_URIS",
    "GmailAuthError",
    "GmailProviderClient",
    "GoogleConfigError",
    "TokenStore",
    "build_authorization_url",
    "build_gmail_service",
    "exchange_code_for_credentials",
    "fetch_gmail_message_resource",
    "generate_oauth_state",
    "get_user_profile",
    "list_new_messages_from_history",
    "parse_gmail_message",
    "start_mailbox_watch",
    "stop_mailbox_watch",
    "sync_gmail_mailbox",
    "validate_and_consume_state",
    "validate_redirect_uri",
]
