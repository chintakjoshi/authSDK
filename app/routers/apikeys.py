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


@router.post("", response_model=APIKeyCreateResponse)
async def create_api_key(
    request: Request,
    payload: APIKeyCreateRequest,
    db_session: Annotated[AsyncSession, Depends(get_database_session)],
    api_key_service: Annotated[APIKeyService, Depends(get_api_key_service)],
    audit_service: Annotated[AuditService, Depends(get_audit_service)],
) -> APIKeyCreateResponse | JSONResponse:
    """Create API key and return raw key exactly once."""
    try:
        created = await api_key_service.create_key(
            db_session=db_session,
            service=payload.service,
            scope=payload.scope,
            user_id=payload.user_id,
            expires_at=payload.expires_at,
        )
    except APIKeyServiceError as exc:
        await audit_service.record(
            db=db_session,
            event_type="api_key.created",
            actor_type="user" if payload.user_id else "system",
            success=False,
            request=request,
            actor_id=str(payload.user_id) if payload.user_id else None,
            target_type="api_key",
            failure_reason=exc.code,
            metadata={"service": payload.service, "scope": payload.scope},
        )
        return _error_response(status_code=exc.status_code, detail=exc.detail, code=exc.code)

    await audit_service.record(
        db=db_session,
        event_type="api_key.created",
        actor_type="user" if created.user_id else "system",
        success=True,
        request=request,
        actor_id=str(created.user_id) if created.user_id else None,
        target_id=str(created.key_id),
        target_type="api_key",
        metadata={"service": created.service, "scope": created.scope},
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
    keys = await api_key_service.list_keys(
        db_session=db_session,
        user_id=user_id,
        service=service,
    )
    await audit_service.record(
        db=db_session,
        event_type="api_key.used",
        actor_type="user" if user_id else "system",
        success=True,
        request=request,
        actor_id=str(user_id) if user_id else None,
        target_type="api_key_collection",
        metadata={"operation": "list", "service": service, "result_count": len(keys)},
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
    try:
        revoked = await api_key_service.revoke_key(db_session=db_session, key_id=key_id)
    except APIKeyServiceError as exc:
        await audit_service.record(
            db=db_session,
            event_type="api_key.revoked",
            actor_type="system",
            success=False,
            request=request,
            target_id=str(key_id),
            target_type="api_key",
            failure_reason=exc.code,
        )
        return _error_response(status_code=exc.status_code, detail=exc.detail, code=exc.code)

    await audit_service.record(
        db=db_session,
        event_type="api_key.revoked",
        actor_type="user" if revoked.user_id else "system",
        success=True,
        request=request,
        actor_id=str(revoked.user_id) if revoked.user_id else None,
        target_id=str(revoked.id),
        target_type="api_key",
        metadata={"service": revoked.service, "scope": revoked.scope},
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
