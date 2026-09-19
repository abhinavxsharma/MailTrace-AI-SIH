"""API router for Google Cloud Pub/Sub push webhook notifications."""

import base64
import json
from typing import Any, Dict, Optional
from fastapi import APIRouter, BackgroundTasks, HTTPException, Request, status
from pydantic import BaseModel, Field

from backend.app.core.logging import logger
from backend.app.services.gmail.sync_service import sync_gmail_mailbox

router = APIRouter()


class PubSubMessage(BaseModel):
    """Google Cloud Pub/Sub message payload model."""

    data: str = Field(..., description="Base64-encoded JSON notification data")
    messageId: Optional[str] = Field(default=None, description="Unique Pub/Sub message ID")
    publishTime: Optional[str] = Field(default=None, description="Publish timestamp")


class PubSubPushNotification(BaseModel):
    """Google Cloud Pub/Sub push delivery schema."""

    message: PubSubMessage
    subscription: Optional[str] = Field(default=None, description="Pub/Sub subscription resource string")


@router.post(
    "/gmail",
    status_code=status.HTTP_200_OK,
    summary="Receive Gmail push notifications from Google Cloud Pub/Sub",
)
async def receive_gmail_pubsub_webhook(
    notification: PubSubPushNotification,
    background_tasks: BackgroundTasks,
) -> Dict[str, Any]:
    """Acknowledge Google Cloud Pub/Sub push notification and schedule in-memory email sync.

    Decodes the notification payload and triggers background synchronization
    into the AnalysisPipeline without blocking the push delivery.
    """
    try:
        raw_data = base64.b64decode(notification.message.data).decode("utf-8")
        parsed_data = json.loads(raw_data)
    except Exception as exc:
        logger.error("Failed to decode Pub/Sub notification payload: %s", str(exc))
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Malformed Pub/Sub message payload.",
        ) from exc

    account_email = parsed_data.get("emailAddress")
    history_id = parsed_data.get("historyId")

    if not account_email:
        logger.warning("Pub/Sub push payload missing emailAddress field")
        return {"status": "ignored", "reason": "missing_email"}

    logger.info(
        "Received Gmail Pub/Sub notification for '%s' (historyId: %s). Queuing background sync.",
        account_email,
        history_id,
    )

    # Dispatch sync in background task so webhook responds immediately with 200 OK
    background_tasks.add_task(
        sync_gmail_mailbox,
        account_email=account_email,
        notification_history_id=str(history_id) if history_id else None,
    )

    return {
        "status": "received",
        "account_email": account_email,
        "history_id": str(history_id) if history_id else None,
    }
