"""Webhook request and response schemas."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import AnyHttpUrl, BaseModel, Field


class WebhookEndpointCreateRequest(BaseModel):
    """Webhook registration payload."""

    name: str = Field(min_length=1, max_length=255)
    url: AnyHttpUrl
    secret: str = Field(min_length=8, max_length=512)
    events: list[str] | None = None


class WebhookEndpointResponse(BaseModel):
    """Webhook endpoint response payload."""

    id: UUID
    name: str
    url: str
    events: list[str]
    is_active: bool
    created_at: datetime


class WebhookDeliveryResponse(BaseModel):
    """Webhook delivery ledger response payload."""

    id: UUID
    endpoint_id: UUID
    event_type: str
    status: str
    attempt_count: int
    last_attempted_at: datetime | None
    next_retry_at: datetime | None
    response_status: int | None
    response_body: str | None
    created_at: datetime


class WebhookRetryResponse(BaseModel):
    """Webhook retry acknowledgement payload."""

    queued: bool
    delivery_id: UUID
