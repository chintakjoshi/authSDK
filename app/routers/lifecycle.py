"""Account lifecycle routes (signup and email verification)."""

from __future__ import annotations

import hmac
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import get_database_session
from app.schemas.lifecycle import (
    ResendVerifyEmailResponse,
    SignupRequest,
    SignupResponse,
    VerifyEmailResponse,
)
from app.services.audit_service import AuditService, get_audit_service
from app.services.lifecycle_service import (
    LifecycleService,
    LifecycleServiceError,
    get_lifecycle_service,
)

router = APIRouter(tags=["lifecycle"])


def _error_response(status_code: int, detail: str, code: str) -> JSONResponse:
    """Build standardized API error response payload."""
    return JSONResponse(status_code=status_code, content={"detail": detail, "code": code})


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


@router.post("/auth/signup", status_code=201, response_model=SignupResponse)
async def signup(
    payload: SignupRequest,
    request: Request,
    db_session: Annotated[AsyncSession, Depends(get_database_session)],
    lifecycle_service: Annotated[LifecycleService, Depends(get_lifecycle_service)],
    audit_service: Annotated[AuditService, Depends(get_audit_service)],
) -> SignupResponse | JSONResponse:
    """Create password user and send signup verification email."""
    try:
        user = await lifecycle_service.signup_password(
            db_session=db_session,
            email=payload.email,
            password=payload.password,
        )
    except LifecycleServiceError as exc:
        await audit_service.record(
            db=db_session,
            event_type="user.created",
            actor_type="user",
            success=False,
            request=request,
            failure_reason=exc.code,
            metadata={"provider": "password"},
        )
        return _error_response(status_code=exc.status_code, detail=exc.detail, code=exc.code)

    await audit_service.record(
        db=db_session,
        event_type="user.created",
        actor_type="user",
        success=True,
        request=request,
        actor_id=str(user.id),
        target_id=str(user.id),
        target_type="user",
        metadata={"provider": "password"},
    )
    return SignupResponse(
        user_id=user.id,
        email=user.email,
        email_verified=user.email_verified,
    )


@router.get("/auth/verify-email", response_model=VerifyEmailResponse)
async def verify_email(
    token: Annotated[str, Query(min_length=16)],
    request: Request,
    db_session: Annotated[AsyncSession, Depends(get_database_session)],
    lifecycle_service: Annotated[LifecycleService, Depends(get_lifecycle_service)],
    audit_service: Annotated[AuditService, Depends(get_audit_service)],
) -> VerifyEmailResponse | JSONResponse:
    """Consume verification token and mark account email as verified."""
    try:
        user = await lifecycle_service.verify_email_token(db_session=db_session, token=token)
    except LifecycleServiceError as exc:
        return _error_response(status_code=exc.status_code, detail=exc.detail, code=exc.code)

    await audit_service.record(
        db=db_session,
        event_type="user.email.verified",
        actor_type="user",
        success=True,
        request=request,
        actor_id=str(user.id),
        target_id=str(user.id),
        target_type="user",
    )
    return VerifyEmailResponse(verified=True)


@router.post("/auth/verify-email/resend", response_model=ResendVerifyEmailResponse)
async def resend_verification_email(
    request: Request,
    db_session: Annotated[AsyncSession, Depends(get_database_session)],
    lifecycle_service: Annotated[LifecycleService, Depends(get_lifecycle_service)],
) -> ResendVerifyEmailResponse | JSONResponse:
    """Resend email verification link for authenticated user."""
    access_token = _extract_bearer_token(request)
    if access_token is None:
        return _error_response(status_code=401, detail="Invalid token.", code="invalid_token")

    try:
        claims = await lifecycle_service.validate_access_token(
            db_session=db_session,
            token=access_token,
        )
        user_id = str(claims.get("sub", "")).strip()
        if not user_id:
            return _error_response(status_code=401, detail="Invalid token.", code="invalid_token")
        await lifecycle_service.resend_verification_email(db_session=db_session, user_id=user_id)
    except LifecycleServiceError as exc:
        return _error_response(status_code=exc.status_code, detail=exc.detail, code=exc.code)

    return ResendVerifyEmailResponse(sent=True)
