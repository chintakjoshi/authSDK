"""Schemas for self-service session and history endpoints."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field


class SelfSessionItem(BaseModel):
    """Self-service session list item."""

    session_id: UUID
    created_at: datetime
    last_seen_at: datetime | None
    expires_at: datetime
    revoked_at: datetime | None
    revoke_reason: str | None
    ip_address: str | None
    user_agent: str | None
    device_label: str
    is_suspicious: bool
    suspicious_reasons: list[str]
    is_current: bool


class SelfSessionRevokeRequest(BaseModel):
    """Optional request body for self-service session revocation."""

    reason: str | None = Field(default=None, min_length=1, max_length=64)


class SelfSessionRevokeResponse(BaseModel):
    """Self-service single-session revocation response."""

    session_id: UUID
    revoke_reason: str


class SelfSessionsRevokedResponse(BaseModel):
    """Self-service bulk session revocation response."""

    revoked_session_ids: list[UUID]
    revoked_session_count: int
    revoke_reason: str


class SelfHistoryItem(BaseModel):
    """Self-service activity-feed item."""

    id: UUID
    event_type: str
    created_at: datetime
    ip_address: str | None
    user_agent: str | None
    success: bool
    failure_reason: str | None
    metadata: dict | None
