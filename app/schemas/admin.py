"""Schemas for admin API requests and responses."""

from __future__ import annotations

from datetime import datetime
from typing import Generic, Literal, TypeVar
from uuid import UUID

from pydantic import AnyHttpUrl, BaseModel, Field

T = TypeVar("T")


class CursorPageResponse(BaseModel, Generic[T]):
    """Standard cursor-paginated admin list response."""

    data: list[T]
    next_cursor: str | None
    has_more: bool


class AdminUserListItem(BaseModel):
    """Admin-facing user summary."""

    id: UUID
    email: str
    role: str
    is_active: bool
    email_verified: bool
    email_otp_enabled: bool
    locked: bool
    lock_retry_after: int | None
    created_at: datetime
    updated_at: datetime


class AdminUserDetail(AdminUserListItem):
    """Admin-facing user detail payload."""

    active_session_count: int


class AdminUserUpdateRequest(BaseModel):
    """Admin role-update payload."""

    role: Literal["admin", "user"]


class AdminUserDeleteResponse(BaseModel):
    """Admin user deletion response."""

    deleted_user_id: UUID
    revoked_session_ids: list[UUID]
    revoked_session_count: int


class AdminUserSessionsRevokedResponse(BaseModel):
    """Admin response for bulk session revocation."""

    user_id: UUID
    revoked_session_ids: list[UUID]
    revoked_session_count: int
    revoke_reason: str


class AdminSessionItem(BaseModel):
    """Admin-facing session list item."""

    session_id: UUID
    user_id: UUID
    created_at: datetime
    last_seen_at: datetime | None
    expires_at: datetime
    revoked_at: datetime | None
    revoke_reason: str | None
    ip_address: str | None
    user_agent: str | None
    device_label: str


class AdminSessionRevokeResponse(BaseModel):
    """Admin response for single-session revocation."""

    user_id: UUID
    session_id: UUID
    revoke_reason: str


class AdminSessionRevokeRequest(BaseModel):
    """Optional request body for admin session revoke endpoints."""

    reason: str | None = Field(default=None, min_length=1, max_length=64)


class AdminUserEraseResponse(BaseModel):
    """Admin response for a completed GDPR erasure."""

    erased_user_id: UUID
    revoked_session_count: int
    revoked_api_key_count: int
    deleted_identity_count: int


class AdminUserOTPUpdateRequest(BaseModel):
    """Admin user OTP-toggle payload."""

    email_otp_enabled: bool


class AdminAPIKeyCreateRequest(BaseModel):
    """Admin API-key creation payload."""

    name: str = Field(min_length=1, max_length=128)
    scope: str = Field(min_length=1, max_length=128)
    expires_at: datetime | None = None


class AdminAPIKeyCreateResponse(BaseModel):
    """Admin API-key creation response with raw key returned once."""

    key_id: UUID
    api_key: str
    key_prefix: str
    name: str
    service: str
    scope: str
    expires_at: datetime | None
    created_at: datetime


class AdminAPIKeyListItem(BaseModel):
    """Admin API-key list item."""

    key_id: UUID
    key_prefix: str
    name: str
    service: str
    scope: str
    expires_at: datetime | None
    revoked_at: datetime | None
    created_at: datetime


class AdminAPIKeyDeleteResponse(BaseModel):
    """Admin API-key revocation response."""

    key_id: UUID
    revoked_at: datetime | None


class AdminOAuthClientCreateRequest(BaseModel):
    """Admin M2M client creation payload."""

    name: str = Field(min_length=1, max_length=255)
    scopes: list[str] = Field(min_length=1)
    token_ttl_seconds: int = Field(default=3600, ge=1)


class AdminOAuthClientUpdateRequest(BaseModel):
    """Admin M2M client update payload."""

    name: str | None = Field(default=None, min_length=1, max_length=255)
    scopes: list[str] | None = None
    token_ttl_seconds: int | None = Field(default=None, ge=1)
    is_active: bool | None = None


class AdminOAuthClientResponse(BaseModel):
    """Admin M2M client response without raw secret."""

    id: UUID
    client_id: str
    client_secret_prefix: str
    name: str
    scopes: list[str]
    is_active: bool
    token_ttl_seconds: int
    created_at: datetime


class AdminOAuthClientCreateResponse(AdminOAuthClientResponse):
    """Admin M2M client creation response with one-time raw secret."""

    client_secret: str


class AdminOAuthClientRotateSecretResponse(BaseModel):
    """Admin M2M client secret rotation response."""

    id: UUID
    client_id: str
    client_secret: str
    client_secret_prefix: str


class AdminWebhookCreateRequest(BaseModel):
    """Admin webhook creation payload."""

    name: str = Field(min_length=1, max_length=255)
    url: AnyHttpUrl
    secret: str = Field(min_length=8, max_length=512)
    events: list[str] | None = None


class AdminWebhookUpdateRequest(BaseModel):
    """Admin webhook update payload."""

    name: str | None = Field(default=None, min_length=1, max_length=255)
    url: AnyHttpUrl | None = None
    events: list[str] | None = None
    is_active: bool | None = None


class AdminWebhookResponse(BaseModel):
    """Admin webhook endpoint response."""

    id: UUID
    name: str
    url: str
    events: list[str]
    is_active: bool
    created_at: datetime


class AdminWebhookDeleteResponse(BaseModel):
    """Admin webhook deletion response."""

    endpoint_id: UUID
    abandoned_delivery_ids: list[UUID]
    abandoned_delivery_count: int


class AdminWebhookDeliveryItem(BaseModel):
    """Admin webhook delivery list item."""

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


class AdminWebhookRetryResponse(BaseModel):
    """Admin webhook retry acknowledgement."""

    queued: Literal[True] = True
    delivery_id: UUID


class AdminAuditLogItem(BaseModel):
    """Admin audit-log list item."""

    id: UUID
    event_type: str
    actor_id: UUID | None
    actor_type: str
    target_id: UUID | None
    target_type: str | None
    ip_address: str | None
    user_agent: str | None
    correlation_id: UUID | None
    success: bool
    failure_reason: str | None
    metadata: dict | None
    created_at: datetime


class AdminSigningKeyRotateResponse(BaseModel):
    """Admin signing-key rotation response."""

    new_kid: str
    retiring_kid: str | None
