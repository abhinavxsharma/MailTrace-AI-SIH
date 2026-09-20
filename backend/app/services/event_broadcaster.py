"""
MAILTRACE AI — Event Broadcaster for Real-Time UI Updates.

Provides lightweight, in-memory Server-Sent Events (SSE) broadcasting so connected
mobile and web clients receive threat alerts and remediation confirmations in <200ms
without polling Gmail repeatedly.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from datetime import datetime, timezone
from typing import Any, AsyncGenerator, Dict, Set

logger = logging.getLogger("mailtrace.events")


class MailboxEventBroadcaster:
    """
    In-memory publisher/subscriber event broker for real-time mailbox threat alerts.
    """

    def __init__(self) -> None:
        self._subscribers: Dict[int, Set[asyncio.Queue]] = {}
        self._lock = asyncio.Lock()

    async def _add_subscriber(self, mailbox_id: int, queue: asyncio.Queue) -> None:
        async with self._lock:
            if mailbox_id not in self._subscribers:
                self._subscribers[mailbox_id] = set()
            self._subscribers[mailbox_id].add(queue)

    async def _remove_subscriber(self, mailbox_id: int, queue: asyncio.Queue) -> None:
        async with self._lock:
            if mailbox_id in self._subscribers:
                self._subscribers[mailbox_id].discard(queue)
                if not self._subscribers[mailbox_id]:
                    del self._subscribers[mailbox_id]

    def subscriber_count(self, mailbox_id: int) -> int:
        """Return count of active client connections listening to a mailbox."""
        return len(self._subscribers.get(mailbox_id, set()))

    def broadcast(
        self,
        mailbox_id: int,
        event_type: str,
        payload: Dict[str, Any],
    ) -> int:
        """
        Non-blocking broadcast of an event to all active subscribers for a mailbox.

        Returns:
            Number of queues the event was pushed to.
        """
        subscribers = self._subscribers.get(mailbox_id)
        if not subscribers:
            return 0

        event_packet = {
            "type": event_type,
            "mailbox_id": mailbox_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "payload": payload,
        }
        event_str = json.dumps(event_packet)
        delivered = 0

        for queue in list(subscribers):
            try:
                queue.put_nowait(event_str)
                delivered += 1
            except asyncio.QueueFull:
                logger.warning(
                    "Event queue full for subscriber on mailbox %s; dropping event %s",
                    mailbox_id,
                    event_type,
                )
            except Exception as exc:
                logger.debug("Failed to deliver event to subscriber: %s", exc)

        logger.debug(
            "Broadcast event '%s' to %d subscriber(s) for mailbox %d",
            event_type,
            delivered,
            mailbox_id,
        )
        return delivered

    async def subscribe(
        self,
        mailbox_id: int,
        heartbeat_interval: float = 15.0,
    ) -> AsyncGenerator[str, None]:
        """
        Yield SSE-formatted event streams with periodic keepalive heartbeats.
        """
        queue: asyncio.Queue = asyncio.Queue(maxsize=100)
        await self._add_subscriber(mailbox_id, queue)

        # Initial handshake event
        handshake = {
            "type": "CONNECTED",
            "mailbox_id": mailbox_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "payload": {"status": "active", "realtime": True},
        }
        yield f"event: connected\ndata: {json.dumps(handshake)}\n\n"

        try:
            while True:
                try:
                    # Wait for next event or heartbeat timeout
                    event_data = await asyncio.wait_for(queue.get(), timeout=heartbeat_interval)
                    yield f"event: message\ndata: {event_data}\n\n"
                except asyncio.TimeoutError:
                    # Keepalive ping to avoid connection drop on proxies/browsers
                    yield f": ping {int(time.time())}\n\n"
        except asyncio.CancelledError:
            pass
        finally:
            await self._remove_subscriber(mailbox_id, queue)


# Global singleton instance
_event_broadcaster: MailboxEventBroadcaster | None = None


def get_event_broadcaster() -> MailboxEventBroadcaster:
    """Obtain global singleton instance of MailboxEventBroadcaster."""
    global _event_broadcaster
    if _event_broadcaster is None:
        _event_broadcaster = MailboxEventBroadcaster()
    return _event_broadcaster


def broadcast_mailbox_event(
    mailbox_id: int,
    event_type: str,
    payload: Dict[str, Any],
) -> int:
    """Convenience helper for broadcasting a mailbox event."""
    return get_event_broadcaster().broadcast(
        mailbox_id=mailbox_id,
        event_type=event_type,
        payload=payload,
    )
