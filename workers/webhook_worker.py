"""RQ job entrypoints for webhook delivery processing."""

from __future__ import annotations

import asyncio
from uuid import UUID

from app.services.webhook_service import get_webhook_service


async def process_webhook_delivery_async(delivery_id: str) -> None:
    """Process one queued webhook delivery by UUID string."""
    await get_webhook_service().process_delivery(delivery_id=UUID(delivery_id))


def process_webhook_delivery(delivery_id: str) -> None:
    """Synchronous RQ wrapper for async webhook delivery processing."""
    asyncio.run(process_webhook_delivery_async(delivery_id))
