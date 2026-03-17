"""API key request/response schemas."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field, model_validator


class APIKeyCreateRequest(BaseModel):
    """Create API key request payload."""

    name: str | None = Field(default=None, min_length=1, max_length=128)
    service: str | None = Field(default=None, min_length=1, max_length=128)
    scope: str = Field(min_length=1, max_length=128)
    user_id: UUID | None = None
    expires_at: datetime | None = None

    @model_validator(mode="after")
    def validate_name_or_service(self) -> APIKeyCreateRequest:
        """Require at least one display identifier for backward compatibility."""
        if self.name is None and self.service is None:
            raise ValueError("Either name or service is required.")
        return self


class APIKeyCreateResponse(BaseModel):
    """Create API key response containing raw key one time."""

    key_id: UUID
    api_key: str
    key_prefix: str
    name: str
    service: str
    scope: str
    user_id: UUID | None
    expires_at: datetime | None
    created_at: datetime


class APIKeyListItem(BaseModel):
    """List API key item."""

    key_id: UUID
    key_prefix: str
    name: str
    service: str
    scope: str
    user_id: UUID | None
    expires_at: datetime | None
    revoked_at: datetime | None
    created_at: datetime


class APIKeyIntrospectRequest(BaseModel):
    """Introspect raw API key request."""

    api_key: str = Field(min_length=4)
