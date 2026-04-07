"""Account lifecycle routes (signup and email verification)."""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, BackgroundTasks, Depends, Query, Request
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.browser_sessions import (
    build_cookie_reauth_response,
    extract_access_token,
    require_csrf_for_cookie_authenticated_request,
)
from app.core.browser_sessions import (
    extract_bearer_token as _shared_extract_bearer_token,
)
from app.dependencies import get_database_session
from app.schemas.lifecycle import (
    EraseAccountResponse,
    ForgotPasswordRequest,
    ForgotPasswordResponse,
    ReauthRequest,
    ReauthResponse,
    ResendVerifyEmailRequest,
    ResendVerifyEmailResponse,
    ResetPasswordRequest,
    ResetPasswordResponse,
    SignupRequest,
    SignupResponse,
    ValidatePasswordResetResponse,
    VerifyEmailResponse,
)
from app.schemas.token import CookieSessionResponse
from app.services.audit_service import AuditService, get_audit_service
from app.services.brute_force_service import extract_client_ip, normalize_user_agent
from app.services.erasure_service import ErasureService, ErasureServiceError, get_erasure_service
from app.services.lifecycle_service import (
    LifecycleService,
    LifecycleServiceError,
    get_lifecycle_service,
)
from app.services.otp_service import OTPService, OTPServiceError, get_otp_service
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
    """Compatibility wrapper for bearer extraction used by existing tests."""
    return _shared_extract_bearer_token(request)


@router.post("/auth/signup", status_code=201, response_model=SignupResponse)
async def signup(
    payload: SignupRequest,
    request: Request,
    background_tasks: BackgroundTasks,
    db_session: Annotated[AsyncSession, Depends(get_database_session)],
    lifecycle_service: Annotated[LifecycleService, Depends(get_lifecycle_service)],
    audit_service: Annotated[AuditService, Depends(get_audit_service)],
    webhook_service: Annotated[WebhookService, Depends(get_webhook_service)],
) -> SignupResponse | JSONResponse:
    """Accept password signup requests without revealing account existence."""
    try:
        signup_result = await lifecycle_service.signup_password(
            db_session=db_session,
            email=payload.email,
            password=payload.password,
        )
    except LifecycleServiceError as exc:
        await audit_service.record(
            db=db_session,
            event_type="user.signup.accepted",
            actor_type="user",
            success=False,
            request=request,
            failure_reason=exc.code,
            metadata={"provider": "password"},
        )
        return _error_response(status_code=exc.status_code, detail=exc.detail, code=exc.code)

    await audit_service.record(
        db=db_session,
        event_type="user.signup.accepted",
        actor_type="user",
        success=True,
        request=request,
        actor_id=(
            str(signup_result.created_user.id) if signup_result.created_user is not None else None
        ),
        target_id=(
            str(signup_result.created_user.id) if signup_result.created_user is not None else None
        ),
        target_type="user" if signup_result.created_user is not None else None,
        metadata={"provider": "password", "created": signup_result.created},
    )
    if signup_result.created_user is not None:
        user = signup_result.created_user
        if signup_result.verification_link is not None:
            background_tasks.add_task(
                lifecycle_service.send_signup_verification_email,
                user_id=str(user.id),
                to_email=user.email,
                verification_link=signup_result.verification_link,
            )
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
    return SignupResponse()


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
    csrf_error = require_csrf_for_cookie_authenticated_request(request)
    if csrf_error is not None:
        return csrf_error

    access_token, _ = extract_access_token(request)
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


@router.post("/auth/verify-email/resend/request", response_model=ResendVerifyEmailResponse)
async def request_verification_email_resend(
    payload: ResendVerifyEmailRequest,
    request: Request,
    db_session: Annotated[AsyncSession, Depends(get_database_session)],
    lifecycle_service: Annotated[LifecycleService, Depends(get_lifecycle_service)],
    audit_service: Annotated[AuditService, Depends(get_audit_service)],
) -> ResendVerifyEmailResponse | JSONResponse:
    """Request a verification resend without requiring an authenticated session."""
    user_id: str | None = None
    try:
        user_id = await lifecycle_service.request_verification_email_resend(
            db_session=db_session,
            email=payload.email,
        )
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
            metadata={"operation": "resend_request"},
        )
        return _error_response(
            status_code=exc.status_code,
            detail=exc.detail,
            code=exc.code,
            headers=exc.headers,
        )

    await audit_service.record(
        db=db_session,
        event_type="user.email.verification_resent",
        actor_type="user",
        success=True,
        request=request,
        actor_id=user_id,
        target_id=user_id,
        target_type="user",
        metadata={"operation": "resend_request"},
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


@router.post("/auth/reauth", response_model=ReauthResponse | CookieSessionResponse)
async def reauthenticate(
    payload: ReauthRequest,
    request: Request,
    db_session: Annotated[AsyncSession, Depends(get_database_session)],
    lifecycle_service: Annotated[LifecycleService, Depends(get_lifecycle_service)],
    audit_service: Annotated[AuditService, Depends(get_audit_service)],
    webhook_service: Annotated[WebhookService, Depends(get_webhook_service)],
) -> ReauthResponse | JSONResponse:
    """Re-verify password and issue a fresh access token with updated auth_time."""
    csrf_error = require_csrf_for_cookie_authenticated_request(request)
    if csrf_error is not None:
        return csrf_error

    access_token, auth_transport = extract_access_token(request)
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
    if auth_transport == "cookie":
        return build_cookie_reauth_response(access_token=fresh_access_token)
    return ReauthResponse(access_token=fresh_access_token)


def _extract_action_token(request: Request) -> str | None:
    """Extract action token from X-Action-Token header."""
    token = request.headers.get("x-action-token", "").strip()
    return token or None


@router.post("/auth/users/me/erase", response_model=EraseAccountResponse)
async def erase_my_account(
    request: Request,
    db_session: Annotated[AsyncSession, Depends(get_database_session)],
    lifecycle_service: Annotated[LifecycleService, Depends(get_lifecycle_service)],
    otp_service: Annotated[OTPService, Depends(get_otp_service)],
    erasure_service: Annotated[ErasureService, Depends(get_erasure_service)],
    audit_service: Annotated[AuditService, Depends(get_audit_service)],
    webhook_service: Annotated[WebhookService, Depends(get_webhook_service)],
) -> EraseAccountResponse | JSONResponse:
    """Erase the authenticated user's account after action-token verification."""
    csrf_error = require_csrf_for_cookie_authenticated_request(request)
    if csrf_error is not None:
        return csrf_error

    access_token, _ = extract_access_token(request)
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
        await otp_service.require_action_token_for_user(
            db_session=db_session,
            token=_extract_action_token(request),
            expected_action="erase_account",
            user_id=user_id,
        )
        result = await erasure_service.erase_user(
            db_session=db_session,
            user_id=UUID(user_id),
        )
    except LifecycleServiceError as exc:
        return _error_response(
            status_code=exc.status_code,
            detail=exc.detail,
            code=exc.code,
            headers=exc.headers,
        )
    except OTPServiceError as exc:
        return _error_response(
            status_code=exc.status_code,
            detail=exc.detail,
            code=exc.code,
            headers=exc.headers,
        )
    except ErasureServiceError as exc:
        return _error_response(
            status_code=exc.status_code,
            detail=exc.detail,
            code=exc.code,
        )

    await audit_service.record(
        db=db_session,
        event_type="user.erased",
        actor_type="user",
        success=True,
        request=request,
        actor_id=str(result.user_id),
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
    return EraseAccountResponse(user_id=result.user_id)
