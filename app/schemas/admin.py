"""Schemas for admin API requests and responses."""

from __future__ import annotations

import ipaddress
from datetime import datetime
from typing import Generic, Literal, TypeVar
from uuid import UUID

from pydantic import AnyHttpUrl, BaseModel, Field, field_validator, model_validator

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
    mfa_enabled: bool
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
    is_suspicious: bool
    suspicious_reasons: list[str]


class AdminSuspiciousSessionItem(AdminSessionItem):
    """Admin-facing global suspicious-session row with user context."""

    user_email: str
    user_role: str


class AdminSessionRevokeResponse(BaseModel):
    """Admin response for single-session revocation."""

    user_id: UUID
    session_id: UUID
    revoke_reason: str


class AdminSessionRevokeRequest(BaseModel):
    """Optional request body for admin session revoke endpoints."""

    reason: str | None = Field(default=None, min_length=1, max_length=64)

    @field_validator("reason", mode="before")
    @classmethod
    def _strip_reason(cls, value: str | None) -> str | None:
        """Trim optional free-form reason input."""
        if isinstance(value, str):
            return value.strip()
        return value


class AdminSessionFilterRevokeRequest(BaseModel):
    """Filterable admin bulk-session revoke payload with safe defaults."""

    is_suspicious: bool | None = None
    created_before: datetime | None = None
    created_after: datetime | None = None
    last_seen_before: datetime | None = None
    last_seen_after: datetime | None = None
    ip_address: str | None = Field(default=None, min_length=1, max_length=45)
    user_agent_contains: str | None = Field(default=None, min_length=1, max_length=128)
    dry_run: bool = False
    reason: str | None = Field(default=None, min_length=1, max_length=64)

    @field_validator("ip_address", "user_agent_contains", "reason", mode="before")
    @classmethod
    def _strip_optional_strings(cls, value: str | None) -> str | None:
        """Trim optional string filters before length validation runs."""
        if isinstance(value, str):
            return value.strip()
        return value

    @field_validator("ip_address")
    @classmethod
    def _normalize_ip_address(cls, value: str | None) -> str | None:
        """Require canonical IP-address filters."""
        if value is None:
            return None
        try:
            return str(ipaddress.ip_address(value))
        except ValueError as exc:
            raise ValueError("IP address must be valid.") from exc

    @model_validator(mode="after")
    def _validate_filter_contract(self) -> AdminSessionFilterRevokeRequest:
        """Require at least one selector and coherent time ranges."""
        has_selector = any(
            (
                self.is_suspicious is not None,
                self.created_before is not None,
                self.created_after is not None,
                self.last_seen_before is not None,
                self.last_seen_after is not None,
                self.ip_address is not None,
                self.user_agent_contains is not None,
            )
        )
        if not has_selector:
            raise ValueError("At least one session filter is required.")
        if (
            self.created_before is not None
            and self.created_after is not None
            and self.created_before < self.created_after
        ):
            raise ValueError("created_before must be on or after created_after.")
        if (
            self.last_seen_before is not None
            and self.last_seen_after is not None
            and self.last_seen_before < self.last_seen_after
        ):
            raise ValueError("last_seen_before must be on or after last_seen_after.")
        return self


class AdminSessionFilteredRevokeResponse(BaseModel):
    """Admin response for filter-based bulk session revocation."""

    user_id: UUID
    matched_session_ids: list[UUID]
    matched_session_count: int
    revoked_session_ids: list[UUID]
    revoked_session_count: int
    dry_run: bool
    revoke_reason: str


class AdminUserEraseResponse(BaseModel):
    """Admin response for a completed GDPR erasure."""

    erased_user_id: UUID
    revoked_session_count: int
    revoked_api_key_count: int
    deleted_identity_count: int


class AdminUserOTPUpdateRequest(BaseModel):
    """Admin user OTP-toggle payload."""

    mfa_enabled: bool


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


class AdminSessionDetail(AdminSessionItem):
    """Admin-facing session detail payload with an embedded attributable timeline."""

    timeline: list[AdminAuditLogItem]


class AdminSigningKeyRotateResponse(BaseModel):
    """Admin signing-key rotation response."""

    new_kid: str
    retiring_kid: str | None
