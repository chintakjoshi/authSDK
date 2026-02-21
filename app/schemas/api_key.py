"""API key request/response schemas."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field


class APIKeyCreateRequest(BaseModel):
    """Create API key request payload."""

    service: str = Field(min_length=1, max_length=128)
    scope: str = Field(min_length=1, max_length=128)
    user_id: UUID | None = None
    expires_at: datetime | None = None


class APIKeyCreateResponse(BaseModel):
    """Create API key response containing raw key one time."""

    key_id: UUID
    api_key: str
    key_prefix: str
    service: str
    scope: str
    user_id: UUID | None
    expires_at: datetime | None
    created_at: datetime


class APIKeyListItem(BaseModel):
    """List API key item."""

    key_id: UUID
    key_prefix: str
    service: str
    scope: str
    user_id: UUID | None
    expires_at: datetime | None
    revoked_at: datetime | None
    created_at: datetime


class APIKeyIntrospectRequest(BaseModel):
    """Introspect raw API key request."""

    api_key: str = Field(min_length=4)
