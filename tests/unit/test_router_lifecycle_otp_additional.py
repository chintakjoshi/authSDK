"""Additional unit tests for lifecycle and OTP router wrappers."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest
from fastapi.requests import Request

from app.core.browser_sessions import get_browser_session_settings
from app.routers import lifecycle as lifecycle_router
from app.routers import otp as otp_router
from app.schemas.lifecycle import ReauthRequest, SignupRequest
from app.schemas.otp import RequestActionOTPRequest, VerifyActionOTPRequest
from app.services.erasure_service import ErasedUserResult, ErasureServiceError
from app.services.lifecycle_service import LifecycleServiceError
from app.services.otp_service import OTPServiceError
from app.services.token_service import TokenPair


def _request(
    *,
    method: str = "POST",
    path: str = "/",
    headers: dict[str, str] | None = None,
) -> Request:
    """Build a minimal Starlette request for direct route invocation."""
    header_list = [
        (key.lower().encode("utf-8"), value.encode("utf-8"))
        for key, value in (headers or {}).items()
    ]

    async def _receive() -> dict[str, object]:
        return {"type": "http.request", "body": b"", "more_body": False}

    return Request(
        {
            "type": "http",
            "method": method,
            "path": path,
            "headers": header_list,
            "client": ("127.0.0.1", 12345),
            "scheme": "http",
            "server": ("testserver", 80),
            "query_string": b"",
        },
        receive=_receive,
    )


class _AuditStub:
    def __init__(self) -> None:
        self.events: list[str] = []

    async def record(self, **kwargs: object) -> None:
        self.events.append(str(kwargs["event_type"]))


class _WebhookStub:
    def __init__(self) -> None:
        self.events: list[str] = []

    async def emit_event(self, *, event_type: str, data: dict[str, object]) -> None:
        del data
        self.events.append(event_type)


class _LifecycleStub:
    def __init__(self) -> None:
        self.validate_claims = {"sub": "user-1"}
        self.signup_error: LifecycleServiceError | None = None
        self.reset_error: LifecycleServiceError | None = None
        self.reauth_error: LifecycleServiceError | None = None

    async def signup_password(self, **kwargs: object) -> object:
        if self.signup_error is not None:
            raise self.signup_error
        return SimpleNamespace(id=uuid4(), email=kwargs["email"], email_verified=False)

    async def validate_access_token(self, **kwargs: object) -> dict[str, object]:
        return self.validate_claims

    async def resend_verification_email(self, **kwargs: object) -> None:
        return None

    async def validate_password_reset_token(self, **kwargs: object) -> None:
        if self.reset_error is not None:
            raise self.reset_error

    async def reauthenticate(self, **kwargs: object) -> str:
        if self.reauth_error is not None:
            raise self.reauth_error
        return "fresh-access-token"


class _OTPStub:
    def __init__(self) -> None:
        self.validate_claims = {"sub": "user-1", "auth_time": int(datetime.now(UTC).timestamp())}
        self.verify_error: OTPServiceError | None = None
        self.require_error: OTPServiceError | None = None
        self.action_valid = False

    async def validate_access_token(self, **kwargs: object) -> dict[str, object]:
        return self.validate_claims

    async def request_action_code(self, **kwargs: object) -> object:
        return SimpleNamespace(user_id="user-1", action=kwargs["action"], expires_in=300)

    async def verify_action_code(self, **kwargs: object) -> object:
        if self.verify_error is not None:
            raise self.verify_error
        return SimpleNamespace(
            user_id="user-1",
            action=kwargs["action"],
            action_token="action-token",
        )

    async def require_action_token_for_user(self, **kwargs: object) -> None:
        if self.require_error is not None:
            raise self.require_error

    async def validate_action_token_for_user(self, **kwargs: object) -> bool:
        return self.action_valid

    async def enable_email_otp(self, **kwargs: object) -> object:
        return SimpleNamespace(id=uuid4(), email_otp_enabled=True)

    async def disable_email_otp(self, **kwargs: object) -> object:
        return SimpleNamespace(id=uuid4(), email_otp_enabled=False)


class _LoginOTPVerifyStub:
    async def verify_login_code(self, **kwargs: object) -> object:
        del kwargs
        return SimpleNamespace(
            user_id="user-1",
            session_id=uuid4(),
            suspicious_login=None,
            token_pair=TokenPair(
                access_token="login-access-token",
                refresh_token="login-refresh-token",
            ),
        )


class _ErasureStub:
    def __init__(self) -> None:
        self.error: ErasureServiceError | None = None

    async def erase_user(self, **kwargs: object) -> ErasedUserResult:
        if self.error is not None:
            raise self.error
        return ErasedUserResult(
            user_id=UUID(str(kwargs["user_id"])),
            anonymized_email="deleted@example.invalid",
            deleted_identity_count=1,
            revoked_session_ids=[],
            revoked_api_key_ids=[],
        )


def _db() -> object:
    return object()


@pytest.mark.asyncio
async def test_lifecycle_routes_cover_signup_resend_validate_reauth_and_erase() -> None:
    """Lifecycle router wrappers cover fail-closed auth handling and success paths."""
    lifecycle_service = _LifecycleStub()
    otp_service = _OTPStub()
    erasure_service = _ErasureStub()
    audit_service = _AuditStub()
    webhook_service = _WebhookStub()

    signed_up = await lifecycle_router.signup(
        payload=SignupRequest(email="user@example.com", password="Password123!"),
        request=_request(path="/auth/signup"),
        db_session=_db(),  # type: ignore[arg-type]
        lifecycle_service=lifecycle_service,  # type: ignore[arg-type]
        audit_service=audit_service,  # type: ignore[arg-type]
        webhook_service=webhook_service,  # type: ignore[arg-type]
    )
    assert signed_up.email == "user@example.com"
    lifecycle_service.signup_error = LifecycleServiceError("bad", "invalid_credentials", 400)
    signup_error = await lifecycle_router.signup(
        payload=SignupRequest(email="bad@example.com", password="Password123!"),
        request=_request(path="/auth/signup"),
        db_session=_db(),  # type: ignore[arg-type]
        lifecycle_service=lifecycle_service,  # type: ignore[arg-type]
        audit_service=audit_service,  # type: ignore[arg-type]
        webhook_service=webhook_service,  # type: ignore[arg-type]
    )
    assert signup_error.status_code == 400

    missing_resend = await lifecycle_router.resend_verification_email(
        request=_request(path="/auth/verify-email/resend"),
        db_session=_db(),  # type: ignore[arg-type]
        lifecycle_service=lifecycle_service,  # type: ignore[arg-type]
        audit_service=audit_service,  # type: ignore[arg-type]
    )
    assert missing_resend.status_code == 401
    lifecycle_service.validate_claims = {"sub": ""}
    blank_resend = await lifecycle_router.resend_verification_email(
        request=_request(
            path="/auth/verify-email/resend",
            headers={"authorization": "Bearer access-token"},
        ),
        db_session=_db(),  # type: ignore[arg-type]
        lifecycle_service=lifecycle_service,  # type: ignore[arg-type]
        audit_service=audit_service,  # type: ignore[arg-type]
    )
    assert blank_resend.status_code == 401

    lifecycle_service.reset_error = LifecycleServiceError("bad", "invalid_reset_token", 400)
    invalid_reset = await lifecycle_router.validate_password_reset_token(
        token="x" * 16,
        db_session=_db(),  # type: ignore[arg-type]
        lifecycle_service=lifecycle_service,  # type: ignore[arg-type]
    )
    assert invalid_reset.status_code == 400
    lifecycle_service.reset_error = None
    valid_reset = await lifecycle_router.validate_password_reset_token(
        token="x" * 16,
        db_session=_db(),  # type: ignore[arg-type]
        lifecycle_service=lifecycle_service,  # type: ignore[arg-type]
    )
    assert valid_reset.valid is True

    missing_reauth = await lifecycle_router.reauthenticate(
        payload=ReauthRequest(password="Password123!"),
        request=_request(path="/auth/reauth"),
        db_session=_db(),  # type: ignore[arg-type]
        lifecycle_service=lifecycle_service,  # type: ignore[arg-type]
        audit_service=audit_service,  # type: ignore[arg-type]
        webhook_service=webhook_service,  # type: ignore[arg-type]
    )
    assert missing_reauth.status_code == 401

    lifecycle_service.validate_claims = {"sub": "user-1"}
    lifecycle_service.reauth_error = LifecycleServiceError("locked", "account_locked", 401)
    locked_reauth = await lifecycle_router.reauthenticate(
        payload=ReauthRequest(password="Password123!"),
        request=_request(
            path="/auth/reauth",
            headers={"authorization": "Bearer access-token"},
        ),
        db_session=_db(),  # type: ignore[arg-type]
        lifecycle_service=lifecycle_service,  # type: ignore[arg-type]
        audit_service=audit_service,  # type: ignore[arg-type]
        webhook_service=webhook_service,  # type: ignore[arg-type]
    )
    assert locked_reauth.status_code == 401
    lifecycle_service.reauth_error = None
    success_reauth = await lifecycle_router.reauthenticate(
        payload=ReauthRequest(password="Password123!"),
        request=_request(
            path="/auth/reauth",
            headers={"authorization": "Bearer access-token"},
        ),
        db_session=_db(),  # type: ignore[arg-type]
        lifecycle_service=lifecycle_service,  # type: ignore[arg-type]
        audit_service=audit_service,  # type: ignore[arg-type]
        webhook_service=webhook_service,  # type: ignore[arg-type]
    )
    assert success_reauth.access_token == "fresh-access-token"

    missing_erase = await lifecycle_router.erase_my_account(
        request=_request(path="/auth/users/me/erase"),
        db_session=_db(),  # type: ignore[arg-type]
        lifecycle_service=lifecycle_service,  # type: ignore[arg-type]
        otp_service=otp_service,  # type: ignore[arg-type]
        erasure_service=erasure_service,  # type: ignore[arg-type]
        audit_service=audit_service,  # type: ignore[arg-type]
        webhook_service=webhook_service,  # type: ignore[arg-type]
    )
    assert missing_erase.status_code == 401
    lifecycle_service.validate_claims = {"sub": ""}
    blank_erase = await lifecycle_router.erase_my_account(
        request=_request(
            path="/auth/users/me/erase",
            headers={"authorization": "Bearer access-token"},
        ),
        db_session=_db(),  # type: ignore[arg-type]
        lifecycle_service=lifecycle_service,  # type: ignore[arg-type]
        otp_service=otp_service,  # type: ignore[arg-type]
        erasure_service=erasure_service,  # type: ignore[arg-type]
        audit_service=audit_service,  # type: ignore[arg-type]
        webhook_service=webhook_service,  # type: ignore[arg-type]
    )
    assert blank_erase.status_code == 401
    lifecycle_service.validate_claims = {"sub": str(uuid4())}
    otp_service.require_error = OTPServiceError("bad", "action_token_invalid", 403)
    otp_failed = await lifecycle_router.erase_my_account(
        request=_request(
            path="/auth/users/me/erase",
            headers={"authorization": "Bearer access-token"},
        ),
        db_session=_db(),  # type: ignore[arg-type]
        lifecycle_service=lifecycle_service,  # type: ignore[arg-type]
        otp_service=otp_service,  # type: ignore[arg-type]
        erasure_service=erasure_service,  # type: ignore[arg-type]
        audit_service=audit_service,  # type: ignore[arg-type]
        webhook_service=webhook_service,  # type: ignore[arg-type]
    )
    assert otp_failed.status_code == 403
    otp_service.require_error = None
    erasure_service.error = ErasureServiceError("gone", "already_erased", 409)
    erase_failed = await lifecycle_router.erase_my_account(
        request=_request(
            path="/auth/users/me/erase",
            headers={"authorization": "Bearer access-token"},
        ),
        db_session=_db(),  # type: ignore[arg-type]
        lifecycle_service=lifecycle_service,  # type: ignore[arg-type]
        otp_service=otp_service,  # type: ignore[arg-type]
        erasure_service=erasure_service,  # type: ignore[arg-type]
        audit_service=audit_service,  # type: ignore[arg-type]
        webhook_service=webhook_service,  # type: ignore[arg-type]
    )
    assert erase_failed.status_code == 409
    erasure_service.error = None
    erased = await lifecycle_router.erase_my_account(
        request=_request(
            path="/auth/users/me/erase",
            headers={
                "authorization": "Bearer access-token",
                "x-action-token": "action-token",
            },
        ),
        db_session=_db(),  # type: ignore[arg-type]
        lifecycle_service=lifecycle_service,  # type: ignore[arg-type]
        otp_service=otp_service,  # type: ignore[arg-type]
        erasure_service=erasure_service,  # type: ignore[arg-type]
        audit_service=audit_service,  # type: ignore[arg-type]
        webhook_service=webhook_service,  # type: ignore[arg-type]
    )
    assert erased.user_id


@pytest.mark.asyncio
async def test_otp_routes_cover_request_verify_and_dual_gate_branches() -> None:
    """OTP route wrappers cover missing auth, verification failure, and dual-gate responses."""
    otp_service = _OTPStub()
    audit_service = _AuditStub()
    webhook_service = _WebhookStub()

    assert otp_router._extract_bearer_token(_request()) is None
    assert (
        otp_router._extract_bearer_token(_request(headers={"authorization": "Basic nope"})) is None
    )
    assert otp_router._auth_time_is_fresh({"auth_time": "bad"}) is False

    missing_request = await otp_router.request_action_otp(
        payload=RequestActionOTPRequest(action="enable_otp"),
        request=_request(path="/auth/otp/request/action"),
        db_session=_db(),  # type: ignore[arg-type]
        otp_service=otp_service,  # type: ignore[arg-type]
        audit_service=audit_service,  # type: ignore[arg-type]
    )
    assert missing_request.status_code == 401
    otp_service.validate_claims = {"sub": ""}
    blank_request = await otp_router.request_action_otp(
        payload=RequestActionOTPRequest(action="enable_otp"),
        request=_request(
            path="/auth/otp/request/action",
            headers={"authorization": "Bearer access-token"},
        ),
        db_session=_db(),  # type: ignore[arg-type]
        otp_service=otp_service,  # type: ignore[arg-type]
        audit_service=audit_service,  # type: ignore[arg-type]
    )
    assert blank_request.status_code == 401
    otp_service.validate_claims = {"sub": "user-1"}
    requested = await otp_router.request_action_otp(
        payload=RequestActionOTPRequest(action="enable_otp"),
        request=_request(
            path="/auth/otp/request/action",
            headers={"authorization": "Bearer access-token"},
        ),
        db_session=_db(),  # type: ignore[arg-type]
        otp_service=otp_service,  # type: ignore[arg-type]
        audit_service=audit_service,  # type: ignore[arg-type]
    )
    assert requested.sent is True

    missing_verify = await otp_router.verify_action_otp(
        payload=VerifyActionOTPRequest(action="enable_otp", code="123456"),
        request=_request(path="/auth/otp/verify/action"),
        db_session=_db(),  # type: ignore[arg-type]
        otp_service=otp_service,  # type: ignore[arg-type]
        audit_service=audit_service,  # type: ignore[arg-type]
        webhook_service=webhook_service,  # type: ignore[arg-type]
    )
    assert missing_verify.status_code == 401
    otp_service.verify_error = OTPServiceError(
        "invalid",
        "invalid_otp",
        401,
        user_id="user-1",
        audit_events=("otp.failed",),
    )
    verify_error = await otp_router.verify_action_otp(
        payload=VerifyActionOTPRequest(action="enable_otp", code="123456"),
        request=_request(
            path="/auth/otp/verify/action",
            headers={"authorization": "Bearer access-token"},
        ),
        db_session=_db(),  # type: ignore[arg-type]
        otp_service=otp_service,  # type: ignore[arg-type]
        audit_service=audit_service,  # type: ignore[arg-type]
        webhook_service=webhook_service,  # type: ignore[arg-type]
    )
    assert verify_error.status_code == 401
    otp_service.verify_error = None
    verified = await otp_router.verify_action_otp(
        payload=VerifyActionOTPRequest(action="enable_otp", code="123456"),
        request=_request(
            path="/auth/otp/verify/action",
            headers={"authorization": "Bearer access-token"},
        ),
        db_session=_db(),  # type: ignore[arg-type]
        otp_service=otp_service,  # type: ignore[arg-type]
        audit_service=audit_service,  # type: ignore[arg-type]
        webhook_service=webhook_service,  # type: ignore[arg-type]
    )
    assert verified.action_token == "action-token"

    missing_enable = await otp_router.enable_email_otp(
        request=_request(path="/auth/otp/enable"),
        db_session=_db(),  # type: ignore[arg-type]
        otp_service=otp_service,  # type: ignore[arg-type]
        audit_service=audit_service,  # type: ignore[arg-type]
    )
    assert missing_enable.status_code == 401
    otp_service.validate_claims = {"sub": "", "auth_time": int(datetime.now(UTC).timestamp())}
    blank_enable = await otp_router.enable_email_otp(
        request=_request(
            path="/auth/otp/enable",
            headers={"authorization": "Bearer access-token"},
        ),
        db_session=_db(),  # type: ignore[arg-type]
        otp_service=otp_service,  # type: ignore[arg-type]
        audit_service=audit_service,  # type: ignore[arg-type]
    )
    assert blank_enable.status_code == 401
    otp_service.validate_claims = {"sub": "user-1", "email_otp_enabled": True}
    otp_required = await otp_router.enable_email_otp(
        request=_request(
            path="/auth/otp/enable",
            headers={"authorization": "Bearer access-token"},
        ),
        db_session=_db(),  # type: ignore[arg-type]
        otp_service=otp_service,  # type: ignore[arg-type]
        audit_service=audit_service,  # type: ignore[arg-type]
    )
    assert otp_required.status_code == 403
    otp_service.validate_claims = {
        "sub": "user-1",
        "email_otp_enabled": False,
        "auth_time": int((datetime.now(UTC) - timedelta(minutes=10)).timestamp()),
    }
    reauth_required = await otp_router.disable_email_otp(
        request=_request(
            path="/auth/otp/disable",
            headers={"authorization": "Bearer access-token"},
        ),
        db_session=_db(),  # type: ignore[arg-type]
        otp_service=otp_service,  # type: ignore[arg-type]
        audit_service=audit_service,  # type: ignore[arg-type]
    )
    assert reauth_required.status_code == 403
    otp_service.validate_claims = {"sub": "user-1", "email_otp_enabled": False}
    otp_service.action_valid = True
    enabled = await otp_router.enable_email_otp(
        request=_request(
            path="/auth/otp/enable",
            headers={
                "authorization": "Bearer access-token",
                "x-action-token": "action-token",
            },
        ),
        db_session=_db(),  # type: ignore[arg-type]
        otp_service=otp_service,  # type: ignore[arg-type]
        audit_service=audit_service,  # type: ignore[arg-type]
    )
    assert enabled.email_otp_enabled is True
    disabled = await otp_router.disable_email_otp(
        request=_request(
            path="/auth/otp/disable",
            headers={
                "authorization": "Bearer access-token",
                "x-action-token": "action-token",
            },
        ),
        db_session=_db(),  # type: ignore[arg-type]
        otp_service=otp_service,  # type: ignore[arg-type]
        audit_service=audit_service,  # type: ignore[arg-type]
    )
    assert disabled.email_otp_enabled is False


@pytest.mark.asyncio
async def test_verify_login_otp_infers_cookie_transport_without_transport_header() -> None:
    """OTP login completion should default to cookie transport from browser-session context."""
    settings = get_browser_session_settings()
    request = _request(
        path="/auth/otp/verify/login",
        headers={
            "cookie": f"{settings.csrf_cookie_name}=csrf-token",
            "x-csrf-token": "csrf-token",
        },
    )

    response = await otp_router.verify_login_otp(
        payload=SimpleNamespace(challenge_token="challenge-token", code="123456"),
        request=request,
        db_session=_db(),  # type: ignore[arg-type]
        otp_service=_LoginOTPVerifyStub(),  # type: ignore[arg-type]
        audit_service=_AuditStub(),  # type: ignore[arg-type]
        webhook_service=_WebhookStub(),  # type: ignore[arg-type]
    )

    assert response.status_code == 200
    assert response.body == b'{"authenticated":true,"session_transport":"cookie"}'
