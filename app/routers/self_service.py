"""Self-service session and activity routes for end users."""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.browser_sessions import extract_bearer_token
from app.core.sessions import SessionService, SessionStateError, get_session_service
from app.core.user_agent import parse_device_label
from app.dependencies import get_database_session
from app.schemas.admin import CursorPageResponse
from app.schemas.self_service import (
    SelfHistoryItem,
    SelfSessionItem,
    SelfSessionRevokeRequest,
    SelfSessionRevokeResponse,
    SelfSessionsRevokedResponse,
)
from app.services.audit_service import AuditService, get_audit_service
from app.services.otp_service import OTPService, OTPServiceError, get_otp_service
from app.services.webhook_service import WebhookService, get_webhook_service

router = APIRouter(tags=["self-service"])


_USER_HISTORY_EVENT_TYPES: list[str] = [
    "user.login.success",
    "user.login.failure",
    "user.login.suspicious",
    "user.logout",
    "session.created",
    "session.revoked",
    "password.reset.requested",
    "password.reset.completed",
    "otp.verified",
    "otp.failed",
    "otp.expired",
    "otp.excessive_failures",
    "otp.admin_toggled",
]

def _error_response(status_code: int, detail: str, code: str) -> JSONResponse:
    """Build standardized API error response payload."""
    return JSONResponse(status_code=status_code, content={"detail": detail, "code": code})


async def _resolve_caller(
    request: Request,
    *,
    db_session: AsyncSession,
    otp_service: OTPService,
) -> tuple[UUID, UUID | None] | JSONResponse:
    """Verify bearer token and return (user_id, current_session_id)."""
    access_token = extract_bearer_token(request)
    if not access_token:
        return _error_response(401, "Invalid token.", "invalid_token")
    try:
        validated = await otp_service.validate_access_token_with_session(
            db_session=db_session,
            token=access_token,
        )
    except OTPServiceError as exc:
        return _error_response(exc.status_code, exc.detail, exc.code)
    claims = validated.claims
    try:
        user_id = UUID(str(claims.get("sub", "")))
    except ValueError:
        return _error_response(401, "Invalid token.", "invalid_token")
    return user_id, validated.session_id


@router.get("/auth/sessions", response_model=CursorPageResponse[SelfSessionItem])
async def list_my_sessions(
    request: Request,
    db_session: Annotated[AsyncSession, Depends(get_database_session)],
    otp_service: Annotated[OTPService, Depends(get_otp_service)],
    session_service: Annotated[SessionService, Depends(get_session_service)],
    status: Annotated[str, Query(pattern="^(active|revoked|all)$")] = "active",
    cursor: Annotated[str | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> CursorPageResponse[SelfSessionItem] | JSONResponse:
    """List the caller's sessions with status filtering."""
    resolved = await _resolve_caller(
        request,
        db_session=db_session,
        otp_service=otp_service,
    )
    if isinstance(resolved, JSONResponse):
        return resolved
    user_id, current_session_id = resolved
    try:
        page = await session_service.list_sessions_for_user(
            db_session=db_session,
            user_id=user_id,
            status=status,
            cursor=cursor,
            limit=limit,
            current_session_id=current_session_id,
        )
    except SessionStateError as exc:
        return _error_response(exc.status_code, exc.detail, exc.code)
    return CursorPageResponse(
        data=[
            SelfSessionItem(
                session_id=row.session_id,
                created_at=row.created_at,
                last_seen_at=row.last_seen_at,
                expires_at=row.expires_at,
                revoked_at=row.revoked_at,
                revoke_reason=row.revoke_reason,
                ip_address=row.ip_address,
                user_agent=row.user_agent,
                device_label=parse_device_label(row.user_agent),
                is_current=row.is_current,
            )
            for row in page.items
        ],
        next_cursor=page.next_cursor,
        has_more=page.has_more,
    )


@router.delete("/auth/sessions/{session_id}", response_model=SelfSessionRevokeResponse)
async def revoke_my_session(
    session_id: UUID,
    request: Request,
    db_session: Annotated[AsyncSession, Depends(get_database_session)],
    otp_service: Annotated[OTPService, Depends(get_otp_service)],
    session_service: Annotated[SessionService, Depends(get_session_service)],
    audit_service: Annotated[AuditService, Depends(get_audit_service)],
    webhook_service: Annotated[WebhookService, Depends(get_webhook_service)],
    payload: SelfSessionRevokeRequest | None = None,
) -> SelfSessionRevokeResponse | JSONResponse:
    """Revoke one of the caller's own sessions (cannot be the current session)."""
    resolved = await _resolve_caller(
        request,
        db_session=db_session,
        otp_service=otp_service,
    )
    if isinstance(resolved, JSONResponse):
        return resolved
    user_id, current_session_id = resolved
    if current_session_id is not None and current_session_id == session_id:
        return _error_response(
            400,
            "Use logout to end the current session.",
            "cannot_revoke_current_session",
        )
    reason = (payload.reason if payload is not None else None) or "self_targeted"
    try:
        revoked_id = await session_service.revoke_one_session(
            db_session=db_session,
            user_id=user_id,
            session_id=session_id,
            reason=reason,
        )
    except SessionStateError as exc:
        return _error_response(exc.status_code, exc.detail, exc.code)

    await audit_service.record(
        db=db_session,
        event_type="session.revoked",
        actor_type="user",
        success=True,
        request=request,
        actor_id=str(user_id),
        target_id=str(user_id),
        target_type="user",
        metadata={"reason": reason, "session_id": str(revoked_id)},
    )
    await webhook_service.emit_event(
        event_type="session.revoked",
        data={
            "user_id": str(user_id),
            "reason": reason,
            "session_ids": [str(revoked_id)],
        },
    )
    return SelfSessionRevokeResponse(session_id=revoked_id, revoke_reason=reason)


@router.delete("/auth/sessions", response_model=SelfSessionsRevokedResponse)
async def revoke_my_other_sessions(
    request: Request,
    db_session: Annotated[AsyncSession, Depends(get_database_session)],
    otp_service: Annotated[OTPService, Depends(get_otp_service)],
    session_service: Annotated[SessionService, Depends(get_session_service)],
    audit_service: Annotated[AuditService, Depends(get_audit_service)],
    webhook_service: Annotated[WebhookService, Depends(get_webhook_service)],
    payload: SelfSessionRevokeRequest | None = None,
) -> SelfSessionsRevokedResponse | JSONResponse:
    """Revoke all the caller's sessions except the current one."""
    resolved = await _resolve_caller(
        request,
        db_session=db_session,
        otp_service=otp_service,
    )
    if isinstance(resolved, JSONResponse):
        return resolved
    user_id, current_session_id = resolved
    reason = (payload.reason if payload is not None else None) or "self_revoke_others"
    try:
        revoked_ids = await session_service.revoke_user_sessions_except(
            db_session=db_session,
            user_id=user_id,
            except_session_id=current_session_id,
            reason=reason,
        )
    except SessionStateError as exc:
        return _error_response(exc.status_code, exc.detail, exc.code)

    await audit_service.record(
        db=db_session,
        event_type="session.revoked",
        actor_type="user",
        success=True,
        request=request,
        actor_id=str(user_id),
        target_id=str(user_id),
        target_type="user",
        metadata={
            "reason": reason,
            "revoked_session_count": len(revoked_ids),
            "session_ids": [str(item) for item in revoked_ids],
        },
    )
    await webhook_service.emit_event(
        event_type="session.revoked",
        data={
            "user_id": str(user_id),
            "reason": reason,
            "session_ids": [str(item) for item in revoked_ids],
        },
    )
    return SelfSessionsRevokedResponse(
        revoked_session_ids=revoked_ids,
        revoked_session_count=len(revoked_ids),
        revoke_reason=reason,
    )


@router.get("/auth/history", response_model=CursorPageResponse[SelfHistoryItem])
async def list_my_history(
    request: Request,
    db_session: Annotated[AsyncSession, Depends(get_database_session)],
    otp_service: Annotated[OTPService, Depends(get_otp_service)],
    audit_service: Annotated[AuditService, Depends(get_audit_service)],
    cursor: Annotated[str | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> CursorPageResponse[SelfHistoryItem] | JSONResponse:
    """Return the caller's recent login, logout, session, password, and OTP events."""
    resolved = await _resolve_caller(
        request,
        db_session=db_session,
        otp_service=otp_service,
    )
    if isinstance(resolved, JSONResponse):
        return resolved
    user_id, _ = resolved
    page = await audit_service.list_events_page(
        db_session=db_session,
        actor_or_target_id=user_id,
        event_types=_USER_HISTORY_EVENT_TYPES,
        cursor=cursor,
        limit=limit,
    )
    return CursorPageResponse(
        data=[
            SelfHistoryItem(
                id=row.id,
                event_type=row.event_type,
                created_at=row.created_at,
                ip_address=str(row.ip_address) if row.ip_address is not None else None,
                user_agent=row.user_agent,
                success=row.success,
                failure_reason=row.failure_reason,
                metadata=row.event_metadata,
            )
            for row in page.items
        ],
        next_cursor=page.next_cursor,
        has_more=page.has_more,
    )
