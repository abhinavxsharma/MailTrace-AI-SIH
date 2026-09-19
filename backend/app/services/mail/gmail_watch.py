"""
MAILTRACE AI — Gmail mailbox watch (push notification) management.

Gmail supports two modes of message retrieval:
1. **Polling** — periodically call ``list_recent_messages()``.
2. **Push (watch)** — register a Pub/Sub topic and receive real-time
   notifications when new messages arrive.

This module implements the **push watch** abstraction via the Gmail
``users.watch`` API endpoint.

IMPORTANT: GOOGLE CLOUD PUB/SUB IS REQUIRED
---------------------------------------------
Gmail push notifications deliver new-mail events to a **Google Cloud
Pub/Sub topic**.  Before calling ``start_watch()``:

1. Create a Google Cloud project.
2. Enable the Gmail API and Cloud Pub/Sub API.
3. Create a Pub/Sub topic.
4. Grant the Gmail service account (``gmail-api-push@system.gserviceaccount.com``)
   the ``roles/pubsub.publisher`` role on the topic.
5. Set environment variables:
       GOOGLE_CLOUD_PROJECT  — your GCP project ID
       GMAIL_PUBSUB_TOPIC    — your Pub/Sub topic name

The actual Pub/Sub consumer (which receives and dispatches notifications
to the forensic pipeline) is intentionally NOT implemented in Chunk 1.
That is part of the watch integration layer in a later chunk.

WATCH EXPIRY
------------
Gmail watch registrations expire after approximately 7 days.
The ``expiration`` field of ``WatchRegistration`` indicates the expiry
time in milliseconds since epoch.  Callers must re-register before expiry.

CONFIGURATION
-------------
Pub/Sub project ID and topic name are read from ``settings``.
Nothing is hardcoded.

TESTABILITY
-----------
All functions accept an injected ``GmailClient`` — no live credentials are
required to test this module.
"""

from __future__ import annotations

from typing import Annotated, Any

from pydantic import BaseModel, Field

from app.core.logging import get_logger
from app.services.mail.gmail_client import GmailClient, GmailClientError

logger = get_logger(__name__)


# --------------------------------------------------------------------------- #
# Models                                                                       #
# --------------------------------------------------------------------------- #

class WatchRegistration(BaseModel):
    """
    Result of a successful Gmail watch registration.

    Fields mirror the Gmail API ``WatchResponse`` resource.

    Attributes:
        history_id:  The current history ID of the mailbox at the time of
                     watch registration.  Use as a starting point when
                     processing history events from the Pub/Sub consumer.
        expiration:  Watch expiration time in milliseconds since the Unix
                     epoch (UTC).  The watch must be renewed before this time.
        topic_name:  The full Pub/Sub topic resource name that was registered,
                     e.g. ``projects/my-project/topics/gmail-push``.
    """

    model_config = {"frozen": True}

    history_id: Annotated[
        str,
        Field(description="Current mailbox history ID at registration time."),
    ]

    expiration: Annotated[
        str,
        Field(description="Watch expiration in milliseconds since Unix epoch (UTC)."),
    ]

    topic_name: Annotated[
        str,
        Field(description="Full Pub/Sub topic resource name used for this watch."),
    ]


# --------------------------------------------------------------------------- #
# Custom exception                                                             #
# --------------------------------------------------------------------------- #

class GmailWatchError(Exception):
    """
    Raised when a Gmail watch operation fails.

    Attributes:
        message: Human-readable description.
    """

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


# --------------------------------------------------------------------------- #
# Public API                                                                   #
# --------------------------------------------------------------------------- #

def start_watch(
    client: GmailClient,
    settings: Any | None = None,
    *,
    label_ids: list[str] | None = None,
) -> WatchRegistration:
    """
    Register a Gmail push notification watch.

    Instructs Gmail to deliver new-mail notifications to the configured
    Google Cloud Pub/Sub topic.  A ``WatchRegistration`` is returned
    containing the history ID to use when consuming subsequent events.

    Args:
        client:    An authenticated ``GmailClient`` instance.
        settings:  Optional ``Settings`` instance.  Defaults to the
                   application singleton.
        label_ids: Label IDs to watch.  Defaults to ``["INBOX"]``.
                   Pass an empty list or None to watch all labels.

    Returns:
        A ``WatchRegistration`` with ``history_id``, ``expiration``,
        and ``topic_name``.

    Raises:
        GmailWatchError:  If the Pub/Sub topic is not configured or
                          the Gmail API call fails.
        GmailClientError: Propagated from ``GmailClient`` on API errors.
    """
    if settings is None:
        from app.core.config import get_settings
        settings = get_settings()

    topic_resource = getattr(settings, "pubsub_topic_resource", "")
    if not topic_resource:
        project = getattr(settings, "GOOGLE_CLOUD_PROJECT", "")
        topic = getattr(settings, "GMAIL_PUBSUB_TOPIC", "")
        raise GmailWatchError(
            "Cannot register Gmail watch: Pub/Sub topic is not configured.  "
            f"Set GOOGLE_CLOUD_PROJECT (current: {project!r}) and "
            f"GMAIL_PUBSUB_TOPIC (current: {topic!r}) environment variables.  "
            "See docs/gmail-connector.md for Pub/Sub setup instructions."
        )

    watch_labels: list[str] = label_ids if label_ids is not None else ["INBOX"]

    request_body: dict[str, Any] = {
        "topicName": topic_resource,
        "labelIds": watch_labels,
        "labelFilterBehavior": "INCLUDE",
    }

    logger.info(
        "Registering Gmail watch on topic=%s labels=%s", topic_resource, watch_labels
    )

    try:
        response: dict[str, Any] = (
            client._service.users()  # noqa: SLF001  — direct access for watch endpoint
            .watch(userId="me", body=request_body)
            .execute()
        )
    except Exception as exc:
        raise GmailClientError(
            f"Gmail watch registration failed: {exc}"
        ) from exc

    registration = WatchRegistration(
        history_id=str(response["historyId"]),
        expiration=str(response["expiration"]),
        topic_name=topic_resource,
    )

    logger.info(
        "Gmail watch registered. history_id=%s expiration=%s",
        registration.history_id,
        registration.expiration,
    )

    return registration


def stop_watch(client: GmailClient) -> None:
    """
    Stop all Gmail push notifications for the authenticated mailbox.

    Calls the Gmail ``users.stop`` API endpoint.  After this call, no
    further Pub/Sub notifications will be delivered until a new watch
    is registered via ``start_watch()``.

    Args:
        client: An authenticated ``GmailClient`` instance.

    Raises:
        GmailClientError: If the API call fails.
    """
    logger.info("Stopping Gmail watch.")

    try:
        client._service.users().stop(userId="me").execute()  # noqa: SLF001
        logger.info("Gmail watch stopped successfully.")
    except Exception as exc:
        raise GmailClientError(f"Failed to stop Gmail watch: {exc}") from exc
