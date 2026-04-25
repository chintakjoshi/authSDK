"""Admin API routes for management, audit inspection, and key rotation."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings, get_settings
from app.core.user_agent import parse_device_label
from app.dependencies import get_database_session
from app.routers._admin_access import require_admin_claims as _require_admin_claims
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
    AdminSessionDetail,
    AdminSessionFilteredRevokeResponse,
    AdminSessionFilterRevokeRequest,
    AdminSessionItem,
    AdminSessionRevokeRequest,
    AdminSessionRevokeResponse,
    AdminSigningKeyRotateResponse,
    AdminSuspiciousSessionItem,
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


def _extract_action_token(request: Request) -> str | None:
    """Extract action token from X-Action-Token header."""
    token = request.headers.get("x-action-token", "").strip()
    return token or None


def _user_list_item(item) -> AdminUserListItem:
    """Convert admin user summary into the API schema."""
    return AdminUserListItem(
        id=item.id,
        email=item.email,
        role=item.role,
        is_active=item.is_active,
        email_verified=item.email_verified,
        mfa_enabled=item.mfa_enabled,
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
        mfa_enabled=item.mfa_enabled,
        locked=item.locked,
        lock_retry_after=item.lock_retry_after,
        created_at=item.created_at,
        updated_at=item.updated_at,
        active_session_count=item.active_session_count,
    )


def _audit_log_item(row) -> AdminAuditLogItem:
    """Convert one audit row into the admin API schema."""
    return AdminAuditLogItem(
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


def _session_item_payload(row) -> dict[str, object]:
    """Serialize shared admin session fields for list and queue responses."""
    return {
        "session_id": row.session_id,
        "user_id": row.user_id,
        "created_at": row.created_at,
        "last_seen_at": row.last_seen_at,
        "expires_at": row.expires_at,
        "revoked_at": row.revoked_at,
        "revoke_reason": row.revoke_reason,
        "ip_address": row.ip_address,
        "user_agent": row.user_agent,
        "device_label": parse_device_label(row.user_agent),
        "is_suspicious": row.is_suspicious,
        "suspicious_reasons": row.suspicious_reasons,
    }


def _session_filter_metadata(payload: AdminSessionFilterRevokeRequest) -> dict[str, object]:
    """Serialize only the explicit filtered-revoke selectors for audit/webhook metadata."""
    metadata: dict[str, object] = {}
    if payload.is_suspicious is not None:
        metadata["is_suspicious"] = payload.is_suspicious
    if payload.created_before is not None:
        metadata["created_before"] = payload.created_before.isoformat()
    if payload.created_after is not None:
        metadata["created_after"] = payload.created_after.isoformat()
    if payload.last_seen_before is not None:
        metadata["last_seen_before"] = payload.last_seen_before.isoformat()
    if payload.last_seen_after is not None:
        metadata["last_seen_after"] = payload.last_seen_after.isoformat()
    if payload.ip_address is not None:
        metadata["ip_address"] = payload.ip_address
    if payload.user_agent_contains is not None:
        metadata["user_agent_contains"] = payload.user_agent_contains
    return metadata


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
    payload: AdminSessionRevokeRequest | None = None,
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
        revoked_session_ids, revoke_reason = await admin_service.revoke_user_sessions(
            db_session=db_session,
            user_id=user_id,
            reason=payload.reason if payload is not None else None,
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
            "reason": revoke_reason,
            "revoked_session_count": len(revoked_session_ids),
            "session_ids": [str(item) for item in revoked_session_ids],
        },
    )
    await webhook_service.emit_event(
        event_type="session.revoked",
        data={
            "user_id": str(user_id),
            "reason": revoke_reason,
            "session_ids": [str(item) for item in revoked_session_ids],
        },
    )
    return AdminUserSessionsRevokedResponse(
        user_id=user_id,
        revoked_session_ids=revoked_session_ids,
        revoked_session_count=len(revoked_session_ids),
        revoke_reason=revoke_reason,
    )


@router.get(
    "/sessions/suspicious",
    response_model=CursorPageResponse[AdminSuspiciousSessionItem],
)
async def list_suspicious_sessions(
    request: Request,
    db_session: Annotated[AsyncSession, Depends(get_database_session)],
    admin_service: Annotated[AdminService, Depends(get_admin_service)],
    email: Annotated[str | None, Query()] = None,
    role: Annotated[str | None, Query()] = None,
    cursor: Annotated[str | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> CursorPageResponse[AdminSuspiciousSessionItem] | JSONResponse:
    """List active suspicious sessions across all users for security triage."""
    try:
        await _require_admin_claims(
            request,
            db_session=db_session,
            admin_service=admin_service,
        )
        page = await admin_service.list_suspicious_sessions_page(
            db_session=db_session,
            email=email,
            role=role,
            cursor=cursor,
            limit=limit,
        )
    except AdminServiceError as exc:
        return _error_response(exc.status_code, exc.detail, exc.code, headers=exc.headers)
    return CursorPageResponse(
        data=[
            AdminSuspiciousSessionItem(
                user_email=row.user_email,
                user_role=row.user_role,
                **_session_item_payload(row),
            )
            for row in page.items
        ],
        next_cursor=page.next_cursor,
        has_more=page.has_more,
    )


@router.get(
    "/users/{user_id}/sessions",
    response_model=CursorPageResponse[AdminSessionItem],
)
async def list_user_sessions(
    user_id: UUID,
    request: Request,
    db_session: Annotated[AsyncSession, Depends(get_database_session)],
    admin_service: Annotated[AdminService, Depends(get_admin_service)],
    status: Annotated[str, Query(pattern="^(active|revoked|all)$")] = "active",
    cursor: Annotated[str | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> CursorPageResponse[AdminSessionItem] | JSONResponse:
    """List sessions for one user with status filtering."""
    try:
        await _require_admin_claims(
            request,
            db_session=db_session,
            admin_service=admin_service,
        )
        page = await admin_service.list_user_sessions_page(
            db_session=db_session,
            user_id=user_id,
            status=status,
            cursor=cursor,
            limit=limit,
        )
    except AdminServiceError as exc:
        return _error_response(exc.status_code, exc.detail, exc.code, headers=exc.headers)
    return CursorPageResponse(
        data=[AdminSessionItem(**_session_item_payload(row)) for row in page.items],
        next_cursor=page.next_cursor,
        has_more=page.has_more,
    )


@router.post(
    "/users/{user_id}/sessions/revoke-by-filter",
    response_model=AdminSessionFilteredRevokeResponse,
)
async def revoke_user_sessions_by_filter(
    user_id: UUID,
    payload: AdminSessionFilterRevokeRequest,
    request: Request,
    db_session: Annotated[AsyncSession, Depends(get_database_session)],
    admin_service: Annotated[AdminService, Depends(get_admin_service)],
    audit_service: Annotated[AuditService, Depends(get_audit_service)],
    webhook_service: Annotated[WebhookService, Depends(get_webhook_service)],
) -> AdminSessionFilteredRevokeResponse | JSONResponse:
    """Preview or revoke active user sessions matching explicit admin filters."""
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
        result = await admin_service.revoke_user_sessions_by_filter(
            db_session=db_session,
            user_id=user_id,
            is_suspicious=payload.is_suspicious,
            created_before=payload.created_before,
            created_after=payload.created_after,
            last_seen_before=payload.last_seen_before,
            last_seen_after=payload.last_seen_after,
            ip_address=payload.ip_address,
            user_agent_contains=payload.user_agent_contains,
            dry_run=payload.dry_run,
            reason=payload.reason,
        )
    except AdminServiceError as exc:
        return _error_response(exc.status_code, exc.detail, exc.code, headers=exc.headers)

    if not result.dry_run:
        filter_metadata = _session_filter_metadata(payload)
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
                "reason": result.revoke_reason,
                "filter": filter_metadata,
                "matched_session_count": len(result.matched_session_ids),
                "revoked_session_count": len(result.revoked_session_ids),
                "session_ids": [str(item) for item in result.revoked_session_ids],
            },
        )
        await webhook_service.emit_event(
            event_type="session.revoked",
            data={
                "user_id": str(user_id),
                "reason": result.revoke_reason,
                "filter": filter_metadata,
                "session_ids": [str(item) for item in result.revoked_session_ids],
            },
        )

    return AdminSessionFilteredRevokeResponse(
        user_id=result.user_id,
        matched_session_ids=result.matched_session_ids,
        matched_session_count=len(result.matched_session_ids),
        revoked_session_ids=result.revoked_session_ids,
        revoked_session_count=len(result.revoked_session_ids),
        dry_run=result.dry_run,
        revoke_reason=result.revoke_reason,
    )


@router.delete(
    "/users/{user_id}/sessions/{session_id}",
    response_model=AdminSessionRevokeResponse,
)
async def revoke_user_session(
    user_id: UUID,
    session_id: UUID,
    request: Request,
    db_session: Annotated[AsyncSession, Depends(get_database_session)],
    admin_service: Annotated[AdminService, Depends(get_admin_service)],
    audit_service: Annotated[AuditService, Depends(get_audit_service)],
    webhook_service: Annotated[WebhookService, Depends(get_webhook_service)],
    payload: AdminSessionRevokeRequest | None = None,
) -> AdminSessionRevokeResponse | JSONResponse:
    """Revoke a single session for the target user."""
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
        revoked_session_id, revoke_reason = await admin_service.revoke_user_session(
            db_session=db_session,
            user_id=user_id,
            session_id=session_id,
            reason=payload.reason if payload is not None else None,
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
            "reason": revoke_reason,
            "session_id": str(revoked_session_id),
        },
    )
    await webhook_service.emit_event(
        event_type="session.revoked",
        data={
            "user_id": str(user_id),
            "reason": revoke_reason,
            "session_ids": [str(revoked_session_id)],
        },
    )
    return AdminSessionRevokeResponse(
        user_id=user_id,
        session_id=revoked_session_id,
        revoke_reason=revoke_reason,
    )


@router.get(
    "/users/{user_id}/sessions/{session_id}",
    response_model=AdminSessionDetail,
)
async def get_user_session_detail(
    user_id: UUID,
    session_id: UUID,
    request: Request,
    db_session: Annotated[AsyncSession, Depends(get_database_session)],
    admin_service: Annotated[AdminService, Depends(get_admin_service)],
    timeline_limit: Annotated[int, Query(ge=1, le=100)] = 20,
) -> AdminSessionDetail | JSONResponse:
    """Return one session plus the latest attributable audit timeline."""
    try:
        await _require_admin_claims(
            request,
            db_session=db_session,
            admin_service=admin_service,
        )
        detail = await admin_service.get_user_session_detail(
            db_session=db_session,
            user_id=user_id,
            session_id=session_id,
            timeline_limit=timeline_limit,
        )
    except AdminServiceError as exc:
        return _error_response(exc.status_code, exc.detail, exc.code, headers=exc.headers)
    return AdminSessionDetail(
        session_id=detail.session_id,
        user_id=detail.user_id,
        created_at=detail.created_at,
        last_seen_at=detail.last_seen_at,
        expires_at=detail.expires_at,
        revoked_at=detail.revoked_at,
        revoke_reason=detail.revoke_reason,
        ip_address=detail.ip_address,
        user_agent=detail.user_agent,
        device_label=parse_device_label(detail.user_agent),
        is_suspicious=detail.is_suspicious,
        suspicious_reasons=detail.suspicious_reasons,
        timeline=[_audit_log_item(row) for row in detail.timeline],
    )


@router.get(
    "/users/{user_id}/history",
    response_model=CursorPageResponse[AdminAuditLogItem],
)
async def list_user_history(
    user_id: UUID,
    request: Request,
    db_session: Annotated[AsyncSession, Depends(get_database_session)],
    admin_service: Annotated[AdminService, Depends(get_admin_service)],
    cursor: Annotated[str | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> CursorPageResponse[AdminAuditLogItem] | JSONResponse:
    """List login, logout, session, OTP, and password-reset events for one user."""
    try:
        await _require_admin_claims(
            request,
            db_session=db_session,
            admin_service=admin_service,
        )
        page = await admin_service.list_user_history_page(
            db_session=db_session,
            user_id=user_id,
            cursor=cursor,
            limit=limit,
        )
    except AdminServiceError as exc:
        return _error_response(exc.status_code, exc.detail, exc.code, headers=exc.headers)
    return CursorPageResponse(
        data=[_audit_log_item(row) for row in page.items],
        next_cursor=page.next_cursor,
        has_more=page.has_more,
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
        user = await admin_service.set_user_mfa(
            db_session=db_session,
            user_id=user_id,
            enabled=payload.mfa_enabled,
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
        metadata={"mfa_enabled": user.mfa_enabled},
    )
    return OTPEnrollmentResponse(mfa_enabled=user.mfa_enabled)


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
