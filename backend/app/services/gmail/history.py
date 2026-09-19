"""Gmail history synchronization, pagination, and expired history ID recovery."""

from typing import List, Optional, Set, Tuple
from googleapiclient.discovery import Resource
from googleapiclient.errors import HttpError

from backend.app.core.logging import logger

FALLBACK_SYNC_LIMIT = 10


def list_new_messages_from_history(
    service: Resource,
    start_history_id: str,
) -> Tuple[List[str], str]:
    """Query Gmail history API for newly added messages since start_history_id.

    Handles pagination and handles expired/invalid history IDs gracefully
    by falling back to a bounded recent message query without bulk downloading.

    Args:
        service: Authenticated Gmail API resource.
        start_history_id: Base history ID to check changes against.

    Returns:
        Tuple of (list_of_new_message_ids, latest_history_id).
    """
    message_ids: Set[str] = set()
    ordered_ids: List[str] = []
    latest_history_id = start_history_id
    page_token: Optional[str] = None

    try:
        while True:
            request = service.users().history().list(
                userId="me",
                startHistoryId=start_history_id,
                historyTypes=["messageAdded"],
                pageToken=page_token,
            )
            response = request.execute()

            # Record latest history ID if returned
            resp_history_id = response.get("historyId")
            if resp_history_id:
                latest_history_id = str(resp_history_id)

            history_records = response.get("history", [])
            for record in history_records:
                messages_added = record.get("messagesAdded", [])
                for item in messages_added:
                    msg = item.get("message", {})
                    msg_id = msg.get("id")
                    if msg_id and msg_id not in message_ids:
                        message_ids.add(msg_id)
                        ordered_ids.append(msg_id)

            page_token = response.get("nextPageToken")
            if not page_token:
                break

        logger.info(
            "Gmail history lookup succeeded: found %d new messages (new history ID: %s)",
            len(ordered_ids),
            latest_history_id,
        )
        return ordered_ids, latest_history_id

    except HttpError as exc:
        # Check for expired or invalid history ID (HTTP 404 or specific error reasons)
        status_code = getattr(exc, "status_code", None)
        error_details = str(exc)
        is_history_expired = (
            status_code == 404
            or "historyId" in error_details
            or "not found" in error_details.lower()
        )

        if is_history_expired:
            logger.warning(
                "Gmail history ID '%s' has expired or is invalid. Initiating bounded fallback sync...",
                start_history_id,
            )
            return _bounded_fallback_sync(service=service)

        logger.error("Gmail history.list failed with unexpected error: %s", error_details, exc_info=True)
        raise


def _bounded_fallback_sync(service: Resource) -> Tuple[List[str], str]:
    """Perform bounded resynchronization when a stored history ID has expired.

    Fetches up to 10 latest messages and current profile history ID to re-baseline.
    Guarantees no bulk mailbox downloading.
    """
    try:
        # Retrieve fresh profile history ID
        profile = service.users().getProfile(userId="me").execute()
        current_history_id = str(profile.get("historyId", ""))

        # Fetch limited recent messages from INBOX
        msg_list_resp = service.users().messages().list(
            userId="me",
            labelIds=["INBOX"],
            maxResults=FALLBACK_SYNC_LIMIT,
        ).execute()

        messages = msg_list_resp.get("messages", [])
        msg_ids = [m["id"] for m in messages if "id" in m]

        logger.info(
            "Bounded fallback sync completed: re-baselined to history ID %s with %d recent messages",
            current_history_id,
            len(msg_ids),
        )
        return msg_ids, current_history_id
    except Exception as exc:
        logger.error("Failed during bounded fallback synchronization: %s", str(exc), exc_info=True)
        raise
