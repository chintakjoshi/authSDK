"""API key management routes."""

from __future__ import annotations

from datetime import UTC
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import get_database_session
from app.schemas.api_key import APIKeyCreateRequest, APIKeyCreateResponse, APIKeyListItem
from app.services.api_key_service import APIKeyService, APIKeyServiceError, get_api_key_service
from app.services.audit_service import AuditService, get_audit_service

router = APIRouter(prefix="/auth/apikeys", tags=["apikeys"])


def _error_response(status_code: int, detail: str, code: str) -> JSONResponse:
    """Build standardized API error response payload."""
    return JSONResponse(status_code=status_code, content={"detail": detail, "code": code})


def _extract_client_ip(request: Request) -> str:
    """Extract client IP using forwarding headers when present."""
    forwarded_for = request.headers.get("x-forwarded-for", "").strip()
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    client = request.client
    return client.host if client else "unknown"


@router.post("", response_model=APIKeyCreateResponse)
async def create_api_key(
    request: Request,
    payload: APIKeyCreateRequest,
    db_session: Annotated[AsyncSession, Depends(get_database_session)],
    api_key_service: Annotated[APIKeyService, Depends(get_api_key_service)],
    audit_service: Annotated[AuditService, Depends(get_audit_service)],
) -> APIKeyCreateResponse | JSONResponse:
    """Create API key and return raw key exactly once."""
    correlation_id = getattr(
        request.state,
        "correlation_id",
        request.headers.get("x-correlation-id", "unknown"),
    )
    client_ip = _extract_client_ip(request)
    try:
        created = await api_key_service.create_key(
            db_session=db_session,
            service=payload.service,
            scope=payload.scope,
            user_id=payload.user_id,
            expires_at=payload.expires_at,
        )
    except APIKeyServiceError as exc:
        audit_service.emit_auth_event(
            event_type="api_key_create",
            provider="api_key",
            ip_address=client_ip,
            correlation_id=correlation_id,
            success=False,
            user_id=str(payload.user_id) if payload.user_id else None,
            service=payload.service,
            scope=payload.scope,
            error_code=exc.code,
        )
        return _error_response(status_code=exc.status_code, detail=exc.detail, code=exc.code)

    audit_service.emit_auth_event(
        event_type="api_key_create",
        provider="api_key",
        ip_address=client_ip,
        correlation_id=correlation_id,
        success=True,
        user_id=str(created.user_id) if created.user_id else None,
        key_id=str(created.key_id),
        key_prefix=created.key_prefix,
        service=created.service,
        scope=created.scope,
    )
    return APIKeyCreateResponse(
        key_id=created.key_id,
        api_key=created.api_key,
        key_prefix=created.key_prefix,
        service=created.service,
        scope=created.scope,
        user_id=created.user_id,
        expires_at=created.expires_at,
        created_at=created.created_at,
    )


@router.get("", response_model=list[APIKeyListItem])
async def list_api_keys(
    request: Request,
    db_session: Annotated[AsyncSession, Depends(get_database_session)],
    api_key_service: Annotated[APIKeyService, Depends(get_api_key_service)],
    audit_service: Annotated[AuditService, Depends(get_audit_service)],
    user_id: Annotated[UUID | None, Query()] = None,
    service: Annotated[str | None, Query()] = None,
) -> list[APIKeyListItem]:
    """List API keys without exposing raw key material."""
    correlation_id = getattr(
        request.state,
        "correlation_id",
        request.headers.get("x-correlation-id", "unknown"),
    )
    client_ip = _extract_client_ip(request)
    keys = await api_key_service.list_keys(
        db_session=db_session,
        user_id=user_id,
        service=service,
    )
    audit_service.emit_auth_event(
        event_type="api_key_list",
        provider="api_key",
        ip_address=client_ip,
        correlation_id=correlation_id,
        success=True,
        user_id=str(user_id) if user_id else None,
        service=service,
        result_count=len(keys),
    )
    return [
        APIKeyListItem(
            key_id=row.id,
            key_prefix=row.key_prefix,
            service=row.service,
            scope=row.scope,
            user_id=row.user_id,
            expires_at=row.expires_at,
            revoked_at=row.revoked_at,
            created_at=row.created_at,
        )
        for row in keys
    ]


@router.post("/{key_id}/revoke")
async def revoke_api_key(
    request: Request,
    key_id: UUID,
    db_session: Annotated[AsyncSession, Depends(get_database_session)],
    api_key_service: Annotated[APIKeyService, Depends(get_api_key_service)],
    audit_service: Annotated[AuditService, Depends(get_audit_service)],
) -> JSONResponse:
    """Revoke API key by key ID."""
    correlation_id = getattr(
        request.state,
        "correlation_id",
        request.headers.get("x-correlation-id", "unknown"),
    )
    client_ip = _extract_client_ip(request)
    try:
        revoked = await api_key_service.revoke_key(db_session=db_session, key_id=key_id)
    except APIKeyServiceError as exc:
        audit_service.emit_auth_event(
            event_type="api_key_revoke",
            provider="api_key",
            ip_address=client_ip,
            correlation_id=correlation_id,
            success=False,
            key_id=str(key_id),
            error_code=exc.code,
        )
        return _error_response(status_code=exc.status_code, detail=exc.detail, code=exc.code)

    audit_service.emit_auth_event(
        event_type="api_key_revoke",
        provider="api_key",
        ip_address=client_ip,
        correlation_id=correlation_id,
        success=True,
        user_id=str(revoked.user_id) if revoked.user_id else None,
        key_id=str(revoked.id),
        key_prefix=revoked.key_prefix,
        service=revoked.service,
        scope=revoked.scope,
    )
    return JSONResponse(
        status_code=200,
        content={
            "detail": "API key revoked.",
            "code": "revoked_api_key",
            "key_id": str(revoked.id),
            "revoked_at": (
                revoked.revoked_at.astimezone(UTC).isoformat() if revoked.revoked_at else None
            ),
        },
    )
