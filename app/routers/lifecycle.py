"""Account lifecycle routes (signup and email verification)."""

from __future__ import annotations

import hmac
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import get_database_session
from app.schemas.lifecycle import (
    ForgotPasswordRequest,
    ForgotPasswordResponse,
    ReauthRequest,
    ReauthResponse,
    ResendVerifyEmailResponse,
    ResetPasswordRequest,
    ResetPasswordResponse,
    SignupRequest,
    SignupResponse,
    ValidatePasswordResetResponse,
    VerifyEmailResponse,
)
from app.services.audit_service import AuditService, get_audit_service
from app.services.brute_force_service import extract_client_ip, normalize_user_agent
from app.services.lifecycle_service import (
    LifecycleService,
    LifecycleServiceError,
    get_lifecycle_service,
)
from app.services.webhook_service import WebhookService, get_webhook_service

router = APIRouter(tags=["lifecycle"])


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


@router.post("/auth/signup", status_code=201, response_model=SignupResponse)
async def signup(
    payload: SignupRequest,
    request: Request,
    db_session: Annotated[AsyncSession, Depends(get_database_session)],
    lifecycle_service: Annotated[LifecycleService, Depends(get_lifecycle_service)],
    audit_service: Annotated[AuditService, Depends(get_audit_service)],
    webhook_service: Annotated[WebhookService, Depends(get_webhook_service)],
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
    await webhook_service.emit_event(
        event_type="user.created",
        data={
            "user_id": str(user.id),
            "email_verified": user.email_verified,
            "provider": "password",
        },
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
    webhook_service: Annotated[WebhookService, Depends(get_webhook_service)],
) -> VerifyEmailResponse | JSONResponse:
    """Consume verification token and mark account email as verified."""
    try:
        user = await lifecycle_service.verify_email_token(db_session=db_session, token=token)
    except LifecycleServiceError as exc:
        await audit_service.record(
            db=db_session,
            event_type="user.email.verified",
            actor_type="user",
            success=False,
            request=request,
            failure_reason=exc.code,
            metadata={"operation": "verify"},
        )
        return _error_response(
            status_code=exc.status_code,
            detail=exc.detail,
            code=exc.code,
            headers=exc.headers,
        )

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
    await webhook_service.emit_event(
        event_type="user.email.verified",
        data={"user_id": str(user.id)},
    )
    return VerifyEmailResponse(verified=True)


@router.post("/auth/verify-email/resend", response_model=ResendVerifyEmailResponse)
async def resend_verification_email(
    request: Request,
    db_session: Annotated[AsyncSession, Depends(get_database_session)],
    lifecycle_service: Annotated[LifecycleService, Depends(get_lifecycle_service)],
    audit_service: Annotated[AuditService, Depends(get_audit_service)],
) -> ResendVerifyEmailResponse | JSONResponse:
    """Resend email verification link for authenticated user."""
    access_token = _extract_bearer_token(request)
    if access_token is None:
        await audit_service.record(
            db=db_session,
            event_type="user.email.verification_resent",
            actor_type="user",
            success=False,
            request=request,
            failure_reason="invalid_token",
            metadata={"operation": "resend"},
        )
        return _error_response(status_code=401, detail="Invalid token.", code="invalid_token")

    user_id: str | None = None
    try:
        claims = await lifecycle_service.validate_access_token(
            db_session=db_session,
            token=access_token,
        )
        user_id = str(claims.get("sub", "")).strip()
        if not user_id:
            await audit_service.record(
                db=db_session,
                event_type="user.email.verification_resent",
                actor_type="user",
                success=False,
                request=request,
                failure_reason="invalid_token",
                metadata={"operation": "resend"},
            )
            return _error_response(status_code=401, detail="Invalid token.", code="invalid_token")
        await lifecycle_service.resend_verification_email(db_session=db_session, user_id=user_id)
    except LifecycleServiceError as exc:
        await audit_service.record(
            db=db_session,
            event_type="user.email.verification_resent",
            actor_type="user",
            success=False,
            request=request,
            actor_id=user_id,
            target_id=user_id,
            target_type="user",
            failure_reason=exc.code,
            metadata={"operation": "resend"},
        )
        return _error_response(status_code=exc.status_code, detail=exc.detail, code=exc.code)

    await audit_service.record(
        db=db_session,
        event_type="user.email.verification_resent",
        actor_type="user",
        success=True,
        request=request,
        actor_id=user_id,
        target_id=user_id,
        target_type="user",
        metadata={"operation": "resend"},
    )
    return ResendVerifyEmailResponse(sent=True)


@router.post("/auth/password/forgot", response_model=ForgotPasswordResponse)
async def forgot_password(
    payload: ForgotPasswordRequest,
    request: Request,
    db_session: Annotated[AsyncSession, Depends(get_database_session)],
    lifecycle_service: Annotated[LifecycleService, Depends(get_lifecycle_service)],
    audit_service: Annotated[AuditService, Depends(get_audit_service)],
) -> ForgotPasswordResponse | JSONResponse:
    """Issue a password reset token without revealing whether the email exists."""
    try:
        user_id = await lifecycle_service.request_password_reset(
            db_session=db_session,
            email=payload.email,
        )
    except LifecycleServiceError as exc:
        await audit_service.record(
            db=db_session,
            event_type="user.password.reset.requested",
            actor_type="user",
            success=False,
            request=request,
            failure_reason=exc.code,
        )
        return _error_response(status_code=exc.status_code, detail=exc.detail, code=exc.code)

    await audit_service.record(
        db=db_session,
        event_type="user.password.reset.requested",
        actor_type="user",
        success=True,
        request=request,
        actor_id=user_id,
        target_id=user_id,
        target_type="user",
    )
    return ForgotPasswordResponse(sent=True)


@router.get("/auth/password/reset", response_model=ValidatePasswordResetResponse)
async def validate_password_reset_token(
    token: Annotated[str, Query(min_length=16, max_length=512)],
    db_session: Annotated[AsyncSession, Depends(get_database_session)],
    lifecycle_service: Annotated[LifecycleService, Depends(get_lifecycle_service)],
) -> ValidatePasswordResetResponse | JSONResponse:
    """Validate password reset token without consuming it."""
    try:
        await lifecycle_service.validate_password_reset_token(db_session=db_session, token=token)
    except LifecycleServiceError as exc:
        return _error_response(status_code=exc.status_code, detail=exc.detail, code=exc.code)
    return ValidatePasswordResetResponse(valid=True)


@router.post("/auth/password/reset", response_model=ResetPasswordResponse)
async def reset_password(
    payload: ResetPasswordRequest,
    request: Request,
    db_session: Annotated[AsyncSession, Depends(get_database_session)],
    lifecycle_service: Annotated[LifecycleService, Depends(get_lifecycle_service)],
    audit_service: Annotated[AuditService, Depends(get_audit_service)],
    webhook_service: Annotated[WebhookService, Depends(get_webhook_service)],
) -> ResetPasswordResponse | JSONResponse:
    """Consume a reset token, set a new password, and revoke all active sessions."""
    user_id: str | None = None
    try:
        user = await lifecycle_service.complete_password_reset(
            db_session=db_session,
            token=payload.token,
            new_password=payload.new_password,
        )
        user_id = str(user.id)
    except LifecycleServiceError as exc:
        await audit_service.record(
            db=db_session,
            event_type="user.password.reset.completed",
            actor_type="user",
            success=False,
            request=request,
            actor_id=user_id,
            target_id=user_id,
            target_type="user",
            failure_reason=exc.code,
        )
        return _error_response(status_code=exc.status_code, detail=exc.detail, code=exc.code)

    await audit_service.record(
        db=db_session,
        event_type="user.password.reset.completed",
        actor_type="user",
        success=True,
        request=request,
        actor_id=user_id,
        target_id=user_id,
        target_type="user",
    )
    if user_id is not None:
        await webhook_service.emit_event(
            event_type="user.password.changed",
            data={"user_id": user_id},
        )
        await webhook_service.emit_event(
            event_type="session.revoked",
            data={"user_id": user_id, "reason": "password_reset"},
        )
    return ResetPasswordResponse(reset=True)


@router.post("/auth/reauth", response_model=ReauthResponse)
async def reauthenticate(
    payload: ReauthRequest,
    request: Request,
    db_session: Annotated[AsyncSession, Depends(get_database_session)],
    lifecycle_service: Annotated[LifecycleService, Depends(get_lifecycle_service)],
    audit_service: Annotated[AuditService, Depends(get_audit_service)],
    webhook_service: Annotated[WebhookService, Depends(get_webhook_service)],
) -> ReauthResponse | JSONResponse:
    """Re-verify password and issue a fresh access token with updated auth_time."""
    access_token = _extract_bearer_token(request)
    if access_token is None:
        await audit_service.record(
            db=db_session,
            event_type="user.reauth.failure",
            actor_type="user",
            success=False,
            request=request,
            failure_reason="invalid_token",
        )
        return _error_response(status_code=401, detail="Invalid token.", code="invalid_token")

    user_id: str | None = None
    try:
        claims = await lifecycle_service.validate_access_token(
            db_session=db_session, token=access_token
        )
        user_id = str(claims.get("sub", "")).strip() or None
        fresh_access_token = await lifecycle_service.reauthenticate(
            db_session=db_session,
            access_token=access_token,
            password=payload.password,
            client_ip=extract_client_ip(request),
            user_agent=normalize_user_agent(request.headers.get("user-agent")),
        )
    except LifecycleServiceError as exc:
        if exc.code == "account_locked" and user_id:
            await audit_service.record(
                db=db_session,
                event_type="user.locked",
                actor_type="user",
                success=False,
                request=request,
                actor_id=user_id,
                target_id=user_id,
                target_type="user",
                failure_reason="account_locked",
            )
            await webhook_service.emit_event(
                event_type="user.locked",
                data={"user_id": user_id, "provider": "password"},
            )
        await audit_service.record(
            db=db_session,
            event_type="user.reauth.failure",
            actor_type="user",
            success=False,
            request=request,
            actor_id=user_id,
            failure_reason=exc.code,
        )
        return _error_response(
            status_code=exc.status_code,
            detail=exc.detail,
            code=exc.code,
            headers=exc.headers,
        )

    await audit_service.record(
        db=db_session,
        event_type="user.reauth.success",
        actor_type="user",
        success=True,
        request=request,
        actor_id=user_id,
    )
    return ReauthResponse(access_token=fresh_access_token)
