"""Admin API routes for management, audit inspection, and key rotation."""

from __future__ import annotations

import hmac
from datetime import datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings, get_settings
from app.dependencies import get_database_session
from app.schemas.admin import (
    AdminAPIKeyCreateRequest,
    AdminAPIKeyCreateResponse,
    AdminAPIKeyDeleteResponse,
    AdminAPIKeyListItem,
    AdminAuditLogItem,
    AdminOAuthClientCreateRequest,
    AdminOAuthClientCreateResponse,
    AdminOAuthClientResponse,
    AdminOAuthClientRotateSecretResponse,
    AdminOAuthClientUpdateRequest,
    AdminSigningKeyRotateResponse,
    AdminUserDeleteResponse,
    AdminUserDetail,
    AdminUserEraseResponse,
    AdminUserListItem,
    AdminUserOTPUpdateRequest,
    AdminUserSessionsRevokedResponse,
    AdminUserUpdateRequest,
    AdminWebhookCreateRequest,
    AdminWebhookDeleteResponse,
    AdminWebhookDeliveryItem,
    AdminWebhookResponse,
    AdminWebhookRetryResponse,
    AdminWebhookUpdateRequest,
    CursorPageResponse,
)
from app.schemas.otp import OTPEnrollmentResponse
from app.services.admin_service import AdminService, AdminServiceError, get_admin_service
from app.services.api_key_service import APIKeyService, APIKeyServiceError, get_api_key_service
from app.services.audit_service import AuditService, get_audit_service
from app.services.m2m_service import M2MService, M2MServiceError, get_m2m_service
from app.services.webhook_service import WebhookService, WebhookServiceError, get_webhook_service

router = APIRouter(prefix="/admin", tags=["admin"])


def _error_response(
    status_code: int,
    detail: str,
    code: str,
    *,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    """Build standardized API error response payload."""
    return JSONResponse(
        status_code=status_code,
        content={"detail": detail, "code": code},
        headers=headers,
    )


def _extract_bearer_token(request: Request) -> str | None:
    """Extract bearer token from Authorization header."""
    authorization = request.headers.get("authorization", "").strip()
    if not authorization:
        return None
    scheme, _, token = authorization.partition(" ")
    if not hmac.compare_digest(scheme.lower(), "bearer"):
        return None
    stripped = token.strip()
    return stripped or None


def _extract_action_token(request: Request) -> str | None:
    """Extract action token from X-Action-Token header."""
    token = request.headers.get("x-action-token", "").strip()
    return token or None


def _extract_admin_api_key(request: Request) -> str | None:
    """Extract local-dev admin bootstrap key from X-Admin-API-Key."""
    token = request.headers.get("x-admin-api-key", "").strip()
    return token or None


async def _require_admin_claims(
    request: Request,
    *,
    db_session: AsyncSession,
    admin_service: AdminService,
) -> dict[str, object]:
    """Validate bearer token and require the admin role."""
    settings = get_settings()
    configured_admin_api_key = settings.admin_api_key
    supplied_admin_api_key = _extract_admin_api_key(request)
    if (
        settings.app.environment == "development"
        and configured_admin_api_key is not None
        and supplied_admin_api_key is not None
        and hmac.compare_digest(
            supplied_admin_api_key,
            configured_admin_api_key.get_secret_value(),
        )
    ):
        claims = {"sub": "local_admin_bootstrap", "role": "admin", "type": "bootstrap_admin"}
        request.state.user = {
            "user_id": None,
            "email": None,
            "role": "admin",
        }
        return claims

    claims = await admin_service.validate_admin_access_token(
        db_session=db_session,
        token=_extract_bearer_token(request),
    )
    request.state.user = {
        "user_id": str(claims.get("sub", "")) or None,
        "email": str(claims.get("email", "")) or None,
        "role": str(claims.get("role", "")) or None,
    }
    return claims


def _user_list_item(item) -> AdminUserListItem:
    """Convert admin user summary into the API schema."""
    return AdminUserListItem(
        id=item.id,
        email=item.email,
        role=item.role,
        is_active=item.is_active,
        email_verified=item.email_verified,
        email_otp_enabled=item.email_otp_enabled,
        locked=item.locked,
        lock_retry_after=item.lock_retry_after,
        created_at=item.created_at,
        updated_at=item.updated_at,
    )


def _user_detail_item(item) -> AdminUserDetail:
    """Convert admin user detail summary into the API schema."""
    return AdminUserDetail(
        id=item.id,
        email=item.email,
        role=item.role,
        is_active=item.is_active,
        email_verified=item.email_verified,
        email_otp_enabled=item.email_otp_enabled,
        locked=item.locked,
        lock_retry_after=item.lock_retry_after,
        created_at=item.created_at,
        updated_at=item.updated_at,
        active_session_count=item.active_session_count,
    )


@router.get("/users", response_model=CursorPageResponse[AdminUserListItem])
async def list_users(
    request: Request,
    db_session: Annotated[AsyncSession, Depends(get_database_session)],
    admin_service: Annotated[AdminService, Depends(get_admin_service)],
    role: Annotated[str | None, Query()] = None,
    email: Annotated[str | None, Query()] = None,
    locked: Annotated[bool | None, Query()] = None,
    cursor: Annotated[str | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> CursorPageResponse[AdminUserListItem] | JSONResponse:
    """List users for admin inspection."""
    try:
        await _require_admin_claims(
            request,
            db_session=db_session,
            admin_service=admin_service,
        )
        page = await admin_service.list_users_page(
            db_session=db_session,
            role=role,
            email=email,
            locked=locked,
            cursor=cursor,
            limit=limit,
        )
    except AdminServiceError as exc:
        return _error_response(exc.status_code, exc.detail, exc.code, headers=exc.headers)
    return CursorPageResponse(
        data=[_user_list_item(item) for item in page.items],
        next_cursor=page.next_cursor,
        has_more=page.has_more,
    )


@router.get("/users/{user_id}", response_model=AdminUserDetail)
async def get_user_detail(
    user_id: UUID,
    request: Request,
    db_session: Annotated[AsyncSession, Depends(get_database_session)],
    admin_service: Annotated[AdminService, Depends(get_admin_service)],
) -> AdminUserDetail | JSONResponse:
    """Return one admin user detail payload."""
    try:
        await _require_admin_claims(
            request,
            db_session=db_session,
            admin_service=admin_service,
        )
        detail = await admin_service.get_user_detail(db_session=db_session, user_id=user_id)
    except AdminServiceError as exc:
        return _error_response(exc.status_code, exc.detail, exc.code, headers=exc.headers)
    return _user_detail_item(detail)


@router.patch("/users/{user_id}", response_model=AdminUserDetail)
async def update_user(
    user_id: UUID,
    payload: AdminUserUpdateRequest,
    request: Request,
    db_session: Annotated[AsyncSession, Depends(get_database_session)],
    admin_service: Annotated[AdminService, Depends(get_admin_service)],
) -> AdminUserDetail | JSONResponse:
    """Update a user role after admin step-up verification."""
    try:
        claims = await _require_admin_claims(
            request,
            db_session=db_session,
            admin_service=admin_service,
        )
        await admin_service.enforce_sensitive_action_gate(
            db_session=db_session,
            claims=claims,
            action="role_change",
            action_token=_extract_action_token(request),
        )
        await admin_service.update_user_role(
            db_session=db_session,
            actor_id=str(claims.get("sub", "")),
            user_id=user_id,
            new_role=payload.role,
            request=request,
        )
        detail = await admin_service.get_user_detail(db_session=db_session, user_id=user_id)
    except AdminServiceError as exc:
        return _error_response(exc.status_code, exc.detail, exc.code, headers=exc.headers)
    return _user_detail_item(detail)


@router.delete("/users/{user_id}", response_model=AdminUserDeleteResponse)
async def delete_user(
    user_id: UUID,
    request: Request,
    db_session: Annotated[AsyncSession, Depends(get_database_session)],
    admin_service: Annotated[AdminService, Depends(get_admin_service)],
    audit_service: Annotated[AuditService, Depends(get_audit_service)],
    webhook_service: Annotated[WebhookService, Depends(get_webhook_service)],
) -> AdminUserDeleteResponse | JSONResponse:
    """Soft-delete a user and revoke all active sessions."""
    try:
        claims = await _require_admin_claims(
            request,
            db_session=db_session,
            admin_service=admin_service,
        )
        await admin_service.enforce_sensitive_action_gate(
            db_session=db_session,
            claims=claims,
            action="delete_user",
            action_token=_extract_action_token(request),
        )
        result = await admin_service.delete_user(db_session=db_session, user_id=user_id)
    except AdminServiceError as exc:
        return _error_response(exc.status_code, exc.detail, exc.code, headers=exc.headers)

    await audit_service.record(
        db=db_session,
        event_type="session.revoked",
        actor_type="admin",
        success=True,
        request=request,
        actor_id=str(claims.get("sub", "")),
        target_id=str(result.user_id),
        target_type="user",
        metadata={
            "reason": "admin_delete",
            "revoked_session_count": len(result.revoked_session_ids),
            "session_ids": [str(item) for item in result.revoked_session_ids],
        },
    )
    await webhook_service.emit_event(
        event_type="session.revoked",
        data={
            "user_id": str(result.user_id),
            "reason": "admin_delete",
            "session_ids": [str(item) for item in result.revoked_session_ids],
        },
    )
    await audit_service.record(
        db=db_session,
        event_type="user.deleted",
        actor_type="admin",
        success=True,
        request=request,
        actor_id=str(claims.get("sub", "")),
        target_id=str(result.user_id),
        target_type="user",
        metadata={"revoked_session_count": len(result.revoked_session_ids)},
    )
    await webhook_service.emit_event(
        event_type="user.deleted",
        data={
            "user_id": str(result.user_id),
            "revoked_session_count": len(result.revoked_session_ids),
        },
    )
    return AdminUserDeleteResponse(
        deleted_user_id=result.user_id,
        revoked_session_ids=result.revoked_session_ids,
        revoked_session_count=len(result.revoked_session_ids),
    )


@router.delete("/users/{user_id}/erase", response_model=AdminUserEraseResponse)
async def erase_user(
    user_id: UUID,
    request: Request,
    db_session: Annotated[AsyncSession, Depends(get_database_session)],
    admin_service: Annotated[AdminService, Depends(get_admin_service)],
    audit_service: Annotated[AuditService, Depends(get_audit_service)],
    webhook_service: Annotated[WebhookService, Depends(get_webhook_service)],
) -> AdminUserEraseResponse | JSONResponse:
    """Erase a user account on behalf of an admin actor."""
    try:
        claims = await _require_admin_claims(
            request,
            db_session=db_session,
            admin_service=admin_service,
        )
        await admin_service.require_action_token(
            db_session=db_session,
            claims=claims,
            action="admin_erase_user",
            action_token=_extract_action_token(request),
        )
        result = await admin_service.erase_user(db_session=db_session, user_id=user_id)
    except AdminServiceError as exc:
        return _error_response(exc.status_code, exc.detail, exc.code, headers=exc.headers)

    await audit_service.record(
        db=db_session,
        event_type="user.erased",
        actor_type="admin",
        success=True,
        request=request,
        actor_id=str(claims.get("sub", "")),
        target_id=str(result.user_id),
        target_type="user",
        metadata={
            "deleted_identity_count": result.deleted_identity_count,
            "revoked_session_count": len(result.revoked_session_ids),
            "revoked_api_key_count": len(result.revoked_api_key_ids),
        },
    )
    await webhook_service.emit_event(
        event_type="user.erased",
        data={
            "user_id": str(result.user_id),
            "deleted_identity_count": result.deleted_identity_count,
            "revoked_session_count": len(result.revoked_session_ids),
            "revoked_api_key_count": len(result.revoked_api_key_ids),
        },
    )
    return AdminUserEraseResponse(
        erased_user_id=result.user_id,
        revoked_session_count=len(result.revoked_session_ids),
        revoked_api_key_count=len(result.revoked_api_key_ids),
        deleted_identity_count=result.deleted_identity_count,
    )


@router.delete("/users/{user_id}/sessions", response_model=AdminUserSessionsRevokedResponse)
async def revoke_user_sessions(
    user_id: UUID,
    request: Request,
    db_session: Annotated[AsyncSession, Depends(get_database_session)],
    admin_service: Annotated[AdminService, Depends(get_admin_service)],
    audit_service: Annotated[AuditService, Depends(get_audit_service)],
    webhook_service: Annotated[WebhookService, Depends(get_webhook_service)],
) -> AdminUserSessionsRevokedResponse | JSONResponse:
    """Revoke all active sessions for a target user."""
    try:
        claims = await _require_admin_claims(
            request,
            db_session=db_session,
            admin_service=admin_service,
        )
        await admin_service.enforce_sensitive_action_gate(
            db_session=db_session,
            claims=claims,
            action="revoke_sessions",
            action_token=_extract_action_token(request),
        )
        revoked_session_ids = await admin_service.revoke_user_sessions(
            db_session=db_session,
            user_id=user_id,
        )
    except AdminServiceError as exc:
        return _error_response(exc.status_code, exc.detail, exc.code, headers=exc.headers)

    await audit_service.record(
        db=db_session,
        event_type="session.revoked",
        actor_type="admin",
        success=True,
        request=request,
        actor_id=str(claims.get("sub", "")),
        target_id=str(user_id),
        target_type="user",
        metadata={
            "reason": "admin_revoke_sessions",
            "revoked_session_count": len(revoked_session_ids),
            "session_ids": [str(item) for item in revoked_session_ids],
        },
    )
    await webhook_service.emit_event(
        event_type="session.revoked",
        data={
            "user_id": str(user_id),
            "reason": "admin_revoke_sessions",
            "session_ids": [str(item) for item in revoked_session_ids],
        },
    )
    return AdminUserSessionsRevokedResponse(
        user_id=user_id,
        revoked_session_ids=revoked_session_ids,
        revoked_session_count=len(revoked_session_ids),
    )


@router.patch("/users/{user_id}/otp", response_model=OTPEnrollmentResponse)
async def update_user_otp(
    user_id: UUID,
    payload: AdminUserOTPUpdateRequest,
    request: Request,
    db_session: Annotated[AsyncSession, Depends(get_database_session)],
    admin_service: Annotated[AdminService, Depends(get_admin_service)],
    audit_service: Annotated[AuditService, Depends(get_audit_service)],
) -> OTPEnrollmentResponse | JSONResponse:
    """Admin-toggle OTP enrollment for a target user."""
    try:
        claims = await _require_admin_claims(
            request,
            db_session=db_session,
            admin_service=admin_service,
        )
        user = await admin_service.set_user_email_otp(
            db_session=db_session,
            user_id=user_id,
            enabled=payload.email_otp_enabled,
        )
    except AdminServiceError as exc:
        return _error_response(exc.status_code, exc.detail, exc.code, headers=exc.headers)

    await audit_service.record(
        db=db_session,
        event_type="otp.admin_toggled",
        actor_type="admin",
        success=True,
        request=request,
        actor_id=str(claims.get("sub", "")),
        target_id=str(user.id),
        target_type="user",
        metadata={"email_otp_enabled": user.email_otp_enabled},
    )
    return OTPEnrollmentResponse(email_otp_enabled=user.email_otp_enabled)


@router.get("/api-keys", response_model=CursorPageResponse[AdminAPIKeyListItem])
async def list_api_keys(
    request: Request,
    db_session: Annotated[AsyncSession, Depends(get_database_session)],
    admin_service: Annotated[AdminService, Depends(get_admin_service)],
    scope: Annotated[str | None, Query()] = None,
    active: Annotated[bool | None, Query()] = None,
    cursor: Annotated[str | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> CursorPageResponse[AdminAPIKeyListItem] | JSONResponse:
    """List API keys for admin inspection."""
    try:
        await _require_admin_claims(
            request,
            db_session=db_session,
            admin_service=admin_service,
        )
        page = await admin_service.list_api_keys_page(
            db_session=db_session,
            scope=scope,
            active=active,
            cursor=cursor,
            limit=limit,
        )
    except AdminServiceError as exc:
        return _error_response(exc.status_code, exc.detail, exc.code, headers=exc.headers)
    return CursorPageResponse(
        data=[
            AdminAPIKeyListItem(
                key_id=row.id,
                key_prefix=row.key_prefix,
                name=row.name,
                service=row.service,
                scope=row.scope,
                expires_at=row.expires_at,
                revoked_at=row.revoked_at,
                created_at=row.created_at,
            )
            for row in page.items
        ],
        next_cursor=page.next_cursor,
        has_more=page.has_more,
    )


@router.post("/api-keys", response_model=AdminAPIKeyCreateResponse)
async def create_api_key(
    payload: AdminAPIKeyCreateRequest,
    request: Request,
    db_session: Annotated[AsyncSession, Depends(get_database_session)],
    admin_service: Annotated[AdminService, Depends(get_admin_service)],
    api_key_service: Annotated[APIKeyService, Depends(get_api_key_service)],
    audit_service: Annotated[AuditService, Depends(get_audit_service)],
    webhook_service: Annotated[WebhookService, Depends(get_webhook_service)],
) -> AdminAPIKeyCreateResponse | JSONResponse:
    """Create an admin-managed API key."""
    try:
        claims = await _require_admin_claims(
            request,
            db_session=db_session,
            admin_service=admin_service,
        )
        created = await api_key_service.create_key(
            db_session=db_session,
            name=payload.name,
            service=None,
            scope=payload.scope,
            user_id=None,
            expires_at=payload.expires_at,
        )
    except (AdminServiceError, APIKeyServiceError) as exc:
        return _error_response(
            exc.status_code,
            exc.detail,
            exc.code,
            headers=getattr(exc, "headers", None),
        )

    await audit_service.record(
        db=db_session,
        event_type="api_key.created",
        actor_type="admin",
        success=True,
        request=request,
        actor_id=str(claims.get("sub", "")),
        target_id=str(created.key_id),
        target_type="api_key",
        metadata={"name": created.name, "service": created.service, "scope": created.scope},
    )
    await webhook_service.emit_event(
        event_type="api_key.created",
        data={
            "key_id": str(created.key_id),
            "name": created.name,
            "service": created.service,
            "scope": created.scope,
        },
    )
    return AdminAPIKeyCreateResponse(
        key_id=created.key_id,
        api_key=created.api_key,
        key_prefix=created.key_prefix,
        name=created.name,
        service=created.service,
        scope=created.scope,
        expires_at=created.expires_at,
        created_at=created.created_at,
    )


@router.delete("/api-keys/{key_id}", response_model=AdminAPIKeyDeleteResponse)
async def revoke_api_key(
    key_id: UUID,
    request: Request,
    db_session: Annotated[AsyncSession, Depends(get_database_session)],
    admin_service: Annotated[AdminService, Depends(get_admin_service)],
    api_key_service: Annotated[APIKeyService, Depends(get_api_key_service)],
    audit_service: Annotated[AuditService, Depends(get_audit_service)],
    webhook_service: Annotated[WebhookService, Depends(get_webhook_service)],
) -> AdminAPIKeyDeleteResponse | JSONResponse:
    """Revoke an admin-managed API key."""
    try:
        claims = await _require_admin_claims(
            request,
            db_session=db_session,
            admin_service=admin_service,
        )
        revoked = await api_key_service.revoke_key(db_session=db_session, key_id=key_id)
    except (AdminServiceError, APIKeyServiceError) as exc:
        return _error_response(
            exc.status_code,
            exc.detail,
            exc.code,
            headers=getattr(exc, "headers", None),
        )

    await audit_service.record(
        db=db_session,
        event_type="api_key.revoked",
        actor_type="admin",
        success=True,
        request=request,
        actor_id=str(claims.get("sub", "")),
        target_id=str(revoked.id),
        target_type="api_key",
        metadata={"name": revoked.name, "service": revoked.service, "scope": revoked.scope},
    )
    await webhook_service.emit_event(
        event_type="api_key.revoked",
        data={
            "key_id": str(revoked.id),
            "name": revoked.name,
            "service": revoked.service,
            "scope": revoked.scope,
        },
    )
    return AdminAPIKeyDeleteResponse(key_id=revoked.id, revoked_at=revoked.revoked_at)


@router.get("/clients", response_model=CursorPageResponse[AdminOAuthClientResponse])
async def list_clients(
    request: Request,
    db_session: Annotated[AsyncSession, Depends(get_database_session)],
    admin_service: Annotated[AdminService, Depends(get_admin_service)],
    active: Annotated[bool | None, Query()] = None,
    cursor: Annotated[str | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> CursorPageResponse[AdminOAuthClientResponse] | JSONResponse:
    """List managed OAuth clients."""
    try:
        await _require_admin_claims(
            request,
            db_session=db_session,
            admin_service=admin_service,
        )
        page = await admin_service.list_clients_page(
            db_session=db_session,
            active=active,
            cursor=cursor,
            limit=limit,
        )
    except AdminServiceError as exc:
        return _error_response(exc.status_code, exc.detail, exc.code, headers=exc.headers)
    return CursorPageResponse(
        data=[
            AdminOAuthClientResponse(
                id=row.id,
                client_id=row.client_id,
                client_secret_prefix=row.client_secret_prefix,
                name=row.name,
                scopes=list(row.scopes),
                is_active=row.is_active,
                token_ttl_seconds=row.token_ttl_seconds,
                created_at=row.created_at,
            )
            for row in page.items
        ],
        next_cursor=page.next_cursor,
        has_more=page.has_more,
    )


@router.post("/clients", response_model=AdminOAuthClientCreateResponse)
async def create_client(
    payload: AdminOAuthClientCreateRequest,
    request: Request,
    db_session: Annotated[AsyncSession, Depends(get_database_session)],
    admin_service: Annotated[AdminService, Depends(get_admin_service)],
    m2m_service: Annotated[M2MService, Depends(get_m2m_service)],
    audit_service: Annotated[AuditService, Depends(get_audit_service)],
    webhook_service: Annotated[WebhookService, Depends(get_webhook_service)],
) -> AdminOAuthClientCreateResponse | JSONResponse:
    """Create an OAuth client for M2M usage."""
    try:
        claims = await _require_admin_claims(
            request,
            db_session=db_session,
            admin_service=admin_service,
        )
        created = await m2m_service.create_client(
            db_session=db_session,
            name=payload.name,
            scopes=payload.scopes,
            token_ttl_seconds=payload.token_ttl_seconds,
        )
    except (AdminServiceError, M2MServiceError) as exc:
        return _error_response(
            exc.status_code,
            exc.detail,
            exc.code,
            headers=getattr(exc, "headers", None),
        )

    await audit_service.record(
        db=db_session,
        event_type="client.created",
        actor_type="admin",
        success=True,
        request=request,
        actor_id=str(claims.get("sub", "")),
        target_id=str(created.id),
        target_type="oauth_client",
        metadata={"client_id": created.client_id, "scopes": created.scopes},
    )
    await webhook_service.emit_event(
        event_type="client.created",
        data={"client_id": created.client_id, "scopes": created.scopes},
    )
    return AdminOAuthClientCreateResponse(
        id=created.id,
        client_id=created.client_id,
        client_secret=created.client_secret,
        client_secret_prefix=created.client_secret_prefix,
        name=created.name,
        scopes=created.scopes,
        is_active=created.is_active,
        token_ttl_seconds=created.token_ttl_seconds,
        created_at=created.created_at,
    )


@router.patch("/clients/{client_id}", response_model=AdminOAuthClientResponse)
async def update_client(
    client_id: UUID,
    payload: AdminOAuthClientUpdateRequest,
    request: Request,
    db_session: Annotated[AsyncSession, Depends(get_database_session)],
    admin_service: Annotated[AdminService, Depends(get_admin_service)],
    m2m_service: Annotated[M2MService, Depends(get_m2m_service)],
    audit_service: Annotated[AuditService, Depends(get_audit_service)],
) -> AdminOAuthClientResponse | JSONResponse:
    """Update mutable OAuth-client fields."""
    try:
        claims = await _require_admin_claims(
            request,
            db_session=db_session,
            admin_service=admin_service,
        )
        updated = await m2m_service.update_client(
            db_session=db_session,
            client_row_id=client_id,
            name=payload.name,
            scopes=payload.scopes,
            token_ttl_seconds=payload.token_ttl_seconds,
            is_active=payload.is_active,
        )
    except (AdminServiceError, M2MServiceError) as exc:
        return _error_response(
            exc.status_code,
            exc.detail,
            exc.code,
            headers=getattr(exc, "headers", None),
        )

    await audit_service.record(
        db=db_session,
        event_type="client.updated.success",
        actor_type="admin",
        success=True,
        request=request,
        actor_id=str(claims.get("sub", "")),
        target_id=str(updated.id),
        target_type="oauth_client",
        metadata={
            "client_id": updated.client_id,
            "scopes": list(updated.scopes),
            "is_active": updated.is_active,
            "token_ttl_seconds": updated.token_ttl_seconds,
        },
    )
    return AdminOAuthClientResponse(
        id=updated.id,
        client_id=updated.client_id,
        client_secret_prefix=updated.client_secret_prefix,
        name=updated.name,
        scopes=list(updated.scopes),
        is_active=updated.is_active,
        token_ttl_seconds=updated.token_ttl_seconds,
        created_at=updated.created_at,
    )


@router.post(
    "/clients/{client_id}/rotate-secret",
    response_model=AdminOAuthClientRotateSecretResponse,
)
async def rotate_client_secret(
    client_id: UUID,
    request: Request,
    db_session: Annotated[AsyncSession, Depends(get_database_session)],
    admin_service: Annotated[AdminService, Depends(get_admin_service)],
    m2m_service: Annotated[M2MService, Depends(get_m2m_service)],
    audit_service: Annotated[AuditService, Depends(get_audit_service)],
    webhook_service: Annotated[WebhookService, Depends(get_webhook_service)],
) -> AdminOAuthClientRotateSecretResponse | JSONResponse:
    """Rotate an OAuth-client secret."""
    try:
        claims = await _require_admin_claims(
            request,
            db_session=db_session,
            admin_service=admin_service,
        )
        rotated = await m2m_service.rotate_client_secret(
            db_session=db_session,
            client_row_id=client_id,
        )
    except (AdminServiceError, M2MServiceError) as exc:
        return _error_response(
            exc.status_code,
            exc.detail,
            exc.code,
            headers=getattr(exc, "headers", None),
        )

    await audit_service.record(
        db=db_session,
        event_type="client.secret_rotated",
        actor_type="admin",
        success=True,
        request=request,
        actor_id=str(claims.get("sub", "")),
        target_id=str(rotated.id),
        target_type="oauth_client",
        metadata={"client_id": rotated.client_id},
    )
    await webhook_service.emit_event(
        event_type="client.secret_rotated",
        data={"client_id": rotated.client_id},
    )
    return AdminOAuthClientRotateSecretResponse(
        id=rotated.id,
        client_id=rotated.client_id,
        client_secret=rotated.client_secret,
        client_secret_prefix=rotated.client_secret_prefix,
    )


@router.delete("/clients/{client_id}", response_model=AdminOAuthClientResponse)
async def delete_client(
    client_id: UUID,
    request: Request,
    db_session: Annotated[AsyncSession, Depends(get_database_session)],
    admin_service: Annotated[AdminService, Depends(get_admin_service)],
    m2m_service: Annotated[M2MService, Depends(get_m2m_service)],
    audit_service: Annotated[AuditService, Depends(get_audit_service)],
) -> AdminOAuthClientResponse | JSONResponse:
    """Soft-delete an OAuth client."""
    try:
        claims = await _require_admin_claims(
            request,
            db_session=db_session,
            admin_service=admin_service,
        )
        deleted = await m2m_service.delete_client(
            db_session=db_session,
            client_row_id=client_id,
        )
    except (AdminServiceError, M2MServiceError) as exc:
        return _error_response(
            exc.status_code,
            exc.detail,
            exc.code,
            headers=getattr(exc, "headers", None),
        )

    await audit_service.record(
        db=db_session,
        event_type="client.deleted.success",
        actor_type="admin",
        success=True,
        request=request,
        actor_id=str(claims.get("sub", "")),
        target_id=str(deleted.id),
        target_type="oauth_client",
        metadata={"client_id": deleted.client_id},
    )
    return AdminOAuthClientResponse(
        id=deleted.id,
        client_id=deleted.client_id,
        client_secret_prefix=deleted.client_secret_prefix,
        name=deleted.name,
        scopes=list(deleted.scopes),
        is_active=deleted.is_active,
        token_ttl_seconds=deleted.token_ttl_seconds,
        created_at=deleted.created_at,
    )


@router.get("/webhooks", response_model=CursorPageResponse[AdminWebhookResponse])
async def list_webhooks(
    request: Request,
    db_session: Annotated[AsyncSession, Depends(get_database_session)],
    admin_service: Annotated[AdminService, Depends(get_admin_service)],
    cursor: Annotated[str | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> CursorPageResponse[AdminWebhookResponse] | JSONResponse:
    """List webhook endpoints."""
    try:
        await _require_admin_claims(
            request,
            db_session=db_session,
            admin_service=admin_service,
        )
        page = await admin_service.list_webhooks_page(
            db_session=db_session,
            cursor=cursor,
            limit=limit,
        )
    except AdminServiceError as exc:
        return _error_response(exc.status_code, exc.detail, exc.code, headers=exc.headers)
    return CursorPageResponse(
        data=[
            AdminWebhookResponse(
                id=row.id,
                name=row.name,
                url=row.url,
                events=list(row.events),
                is_active=row.is_active,
                created_at=row.created_at,
            )
            for row in page.items
        ],
        next_cursor=page.next_cursor,
        has_more=page.has_more,
    )


@router.post("/webhooks", response_model=AdminWebhookResponse)
async def create_webhook(
    payload: AdminWebhookCreateRequest,
    request: Request,
    db_session: Annotated[AsyncSession, Depends(get_database_session)],
    admin_service: Annotated[AdminService, Depends(get_admin_service)],
    webhook_service: Annotated[WebhookService, Depends(get_webhook_service)],
    audit_service: Annotated[AuditService, Depends(get_audit_service)],
) -> AdminWebhookResponse | JSONResponse:
    """Register a webhook endpoint."""
    try:
        claims = await _require_admin_claims(
            request,
            db_session=db_session,
            admin_service=admin_service,
        )
        endpoint = await webhook_service.register_endpoint(
            db_session=db_session,
            name=payload.name,
            url=str(payload.url),
            secret=payload.secret,
            events=payload.events,
        )
    except (AdminServiceError, WebhookServiceError) as exc:
        return _error_response(
            exc.status_code,
            exc.detail,
            exc.code,
            headers=getattr(exc, "headers", None),
        )

    await audit_service.record(
        db=db_session,
        event_type="webhook.created.success",
        actor_type="admin",
        success=True,
        request=request,
        actor_id=str(claims.get("sub", "")),
        target_id=str(endpoint.id),
        target_type="webhook_endpoint",
        metadata={"name": endpoint.name, "url": endpoint.url, "events": endpoint.events},
    )
    return AdminWebhookResponse(
        id=endpoint.id,
        name=endpoint.name,
        url=endpoint.url,
        events=endpoint.events,
        is_active=endpoint.is_active,
        created_at=endpoint.created_at,
    )


@router.patch("/webhooks/{endpoint_id}", response_model=AdminWebhookResponse)
async def update_webhook(
    endpoint_id: UUID,
    payload: AdminWebhookUpdateRequest,
    request: Request,
    db_session: Annotated[AsyncSession, Depends(get_database_session)],
    admin_service: Annotated[AdminService, Depends(get_admin_service)],
    audit_service: Annotated[AuditService, Depends(get_audit_service)],
) -> AdminWebhookResponse | JSONResponse:
    """Update a webhook endpoint."""
    try:
        claims = await _require_admin_claims(
            request,
            db_session=db_session,
            admin_service=admin_service,
        )
        endpoint = await admin_service.update_webhook(
            db_session=db_session,
            endpoint_id=endpoint_id,
            name=payload.name,
            url=str(payload.url) if payload.url is not None else None,
            events=payload.events,
            is_active=payload.is_active,
        )
    except AdminServiceError as exc:
        return _error_response(exc.status_code, exc.detail, exc.code, headers=exc.headers)

    await audit_service.record(
        db=db_session,
        event_type="webhook.updated.success",
        actor_type="admin",
        success=True,
        request=request,
        actor_id=str(claims.get("sub", "")),
        target_id=str(endpoint.id),
        target_type="webhook_endpoint",
        metadata={
            "name": endpoint.name,
            "url": endpoint.url,
            "events": list(endpoint.events),
            "is_active": endpoint.is_active,
        },
    )
    return AdminWebhookResponse(
        id=endpoint.id,
        name=endpoint.name,
        url=endpoint.url,
        events=list(endpoint.events),
        is_active=endpoint.is_active,
        created_at=endpoint.created_at,
    )


@router.delete("/webhooks/{endpoint_id}", response_model=AdminWebhookDeleteResponse)
async def delete_webhook(
    endpoint_id: UUID,
    request: Request,
    db_session: Annotated[AsyncSession, Depends(get_database_session)],
    admin_service: Annotated[AdminService, Depends(get_admin_service)],
    audit_service: Annotated[AuditService, Depends(get_audit_service)],
) -> AdminWebhookDeleteResponse | JSONResponse:
    """Delete a webhook endpoint and abandon pending deliveries."""
    try:
        claims = await _require_admin_claims(
            request,
            db_session=db_session,
            admin_service=admin_service,
        )
        deleted = await admin_service.delete_webhook(db_session=db_session, endpoint_id=endpoint_id)
    except AdminServiceError as exc:
        return _error_response(exc.status_code, exc.detail, exc.code, headers=exc.headers)

    await audit_service.record(
        db=db_session,
        event_type="webhook.deleted.success",
        actor_type="admin",
        success=True,
        request=request,
        actor_id=str(claims.get("sub", "")),
        target_id=str(deleted.id),
        target_type="webhook_endpoint",
        metadata={"abandoned_delivery_ids": [str(item) for item in deleted.abandoned_delivery_ids]},
    )
    return AdminWebhookDeleteResponse(
        endpoint_id=deleted.id,
        abandoned_delivery_ids=deleted.abandoned_delivery_ids,
        abandoned_delivery_count=len(deleted.abandoned_delivery_ids),
    )


@router.get(
    "/webhooks/{endpoint_id}/deliveries",
    response_model=CursorPageResponse[AdminWebhookDeliveryItem],
)
async def list_webhook_deliveries(
    endpoint_id: UUID,
    request: Request,
    db_session: Annotated[AsyncSession, Depends(get_database_session)],
    admin_service: Annotated[AdminService, Depends(get_admin_service)],
    status: Annotated[str | None, Query()] = None,
    cursor: Annotated[str | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> CursorPageResponse[AdminWebhookDeliveryItem] | JSONResponse:
    """List deliveries for a webhook endpoint."""
    try:
        await _require_admin_claims(
            request,
            db_session=db_session,
            admin_service=admin_service,
        )
        page = await admin_service.list_webhook_deliveries_page(
            db_session=db_session,
            endpoint_id=endpoint_id,
            status=status,
            cursor=cursor,
            limit=limit,
        )
    except AdminServiceError as exc:
        return _error_response(exc.status_code, exc.detail, exc.code, headers=exc.headers)
    return CursorPageResponse(
        data=[
            AdminWebhookDeliveryItem(
                id=row.id,
                endpoint_id=row.endpoint_id,
                event_type=row.event_type,
                status=row.status,
                attempt_count=row.attempt_count,
                last_attempted_at=row.last_attempted_at,
                next_retry_at=row.next_retry_at,
                response_status=row.response_status,
                response_body=row.response_body,
                created_at=row.created_at,
            )
            for row in page.items
        ],
        next_cursor=page.next_cursor,
        has_more=page.has_more,
    )


@router.post("/webhooks/deliveries/{delivery_id}/retry", response_model=AdminWebhookRetryResponse)
async def retry_webhook_delivery(
    delivery_id: UUID,
    request: Request,
    db_session: Annotated[AsyncSession, Depends(get_database_session)],
    admin_service: Annotated[AdminService, Depends(get_admin_service)],
    webhook_service: Annotated[WebhookService, Depends(get_webhook_service)],
    audit_service: Annotated[AuditService, Depends(get_audit_service)],
) -> AdminWebhookRetryResponse | JSONResponse:
    """Reset and requeue a webhook delivery."""
    try:
        claims = await _require_admin_claims(
            request,
            db_session=db_session,
            admin_service=admin_service,
        )
        delivery = await webhook_service.retry_delivery(
            db_session=db_session,
            delivery_id=delivery_id,
        )
    except (AdminServiceError, WebhookServiceError) as exc:
        return _error_response(
            exc.status_code,
            exc.detail,
            exc.code,
            headers=getattr(exc, "headers", None),
        )

    await audit_service.record(
        db=db_session,
        event_type="webhook.retry.queued",
        actor_type="admin",
        success=True,
        request=request,
        actor_id=str(claims.get("sub", "")),
        target_id=str(delivery.id),
        target_type="webhook_delivery",
        metadata={"endpoint_id": str(delivery.endpoint_id)},
    )
    return AdminWebhookRetryResponse(delivery_id=delivery.id)


@router.get("/audit-log", response_model=CursorPageResponse[AdminAuditLogItem])
async def list_audit_log(
    request: Request,
    db_session: Annotated[AsyncSession, Depends(get_database_session)],
    admin_service: Annotated[AdminService, Depends(get_admin_service)],
    actor_id: Annotated[UUID | None, Query()] = None,
    event_type: Annotated[str | None, Query()] = None,
    success: Annotated[bool | None, Query()] = None,
    date_from: Annotated[datetime | None, Query()] = None,
    date_to: Annotated[datetime | None, Query()] = None,
    cursor: Annotated[str | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> CursorPageResponse[AdminAuditLogItem] | JSONResponse:
    """List audit-log entries with cursor pagination."""
    try:
        await _require_admin_claims(
            request,
            db_session=db_session,
            admin_service=admin_service,
        )
        page = await admin_service.list_audit_log_page(
            db_session=db_session,
            actor_id=actor_id,
            event_type=event_type,
            success=success,
            date_from=date_from,
            date_to=date_to,
            cursor=cursor,
            limit=limit,
        )
    except AdminServiceError as exc:
        return _error_response(exc.status_code, exc.detail, exc.code, headers=exc.headers)
    return CursorPageResponse(
        data=[
            AdminAuditLogItem(
                id=row.id,
                event_type=row.event_type,
                actor_id=row.actor_id,
                actor_type=row.actor_type.value,
                target_id=row.target_id,
                target_type=row.target_type,
                ip_address=str(row.ip_address) if row.ip_address is not None else None,
                user_agent=row.user_agent,
                correlation_id=row.correlation_id,
                success=row.success,
                failure_reason=row.failure_reason,
                metadata=row.event_metadata,
                created_at=row.created_at,
            )
            for row in page.items
        ],
        next_cursor=page.next_cursor,
        has_more=page.has_more,
    )


@router.post("/signing-keys/rotate", response_model=AdminSigningKeyRotateResponse)
async def rotate_signing_key(
    request: Request,
    db_session: Annotated[AsyncSession, Depends(get_database_session)],
    admin_service: Annotated[AdminService, Depends(get_admin_service)],
    audit_service: Annotated[AuditService, Depends(get_audit_service)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> AdminSigningKeyRotateResponse | JSONResponse:
    """Rotate the active signing key after admin step-up verification."""
    try:
        claims = await _require_admin_claims(
            request,
            db_session=db_session,
            admin_service=admin_service,
        )
        await admin_service.enforce_sensitive_action_gate(
            db_session=db_session,
            claims=claims,
            action="rotate_signing_key",
            action_token=_extract_action_token(request),
        )
        result = await admin_service.rotate_signing_key(
            db_session=db_session,
            rotation_overlap_seconds=settings.signing_keys.rotation_overlap_seconds,
        )
    except AdminServiceError as exc:
        return _error_response(exc.status_code, exc.detail, exc.code, headers=exc.headers)

    await audit_service.record(
        db=db_session,
        event_type="signing_key.rotate.success",
        actor_type="admin",
        success=True,
        request=request,
        actor_id=str(claims.get("sub", "")),
        metadata={"new_kid": result.new_kid, "retiring_kid": result.retiring_kid},
    )
    return AdminSigningKeyRotateResponse(
        new_kid=result.new_kid,
        retiring_kid=result.retiring_kid,
    )
