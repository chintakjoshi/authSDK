"""Additional unit tests for auth route wrapper branches."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi.requests import Request

from app.core.sessions import SessionStateError
from app.routers import auth as auth_router
from app.schemas.token import LogoutRequest
from app.schemas.user import LoginRequest
from app.services.brute_force_service import BruteForceProtectionError
from app.services.token_service import TokenPair


def _request(
    *,
    path: str,
    headers: dict[str, str] | None = None,
    body: bytes = b"",
) -> Request:
    """Build a Starlette request for direct route invocation."""
    header_list = [
        (key.lower().encode("utf-8"), value.encode("utf-8"))
        for key, value in (headers or {}).items()
    ]
    sent = False

    async def _receive() -> dict[str, object]:
        nonlocal sent
        if sent:
            return {"type": "http.request", "body": b"", "more_body": False}
        sent = True
        return {"type": "http.request", "body": body, "more_body": False}

    return Request(
        {
            "type": "http",
            "method": "POST",
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
    async def record(self, **kwargs: object) -> None:
        return None


class _WebhookStub:
    async def emit_event(self, *, event_type: str, data: dict[str, object]) -> None:
        del event_type, data


class _UserServiceStub:
    def __init__(self) -> None:
        self.user = None
        self.verify_password_result = False

    async def get_user_by_email(self, **kwargs: object) -> object | None:
        return self.user

    def dummy_verify(self) -> None:
        return None

    def verify_password(self, **kwargs: object) -> bool:
        return self.verify_password_result


class _BruteForceStub:
    def __init__(self) -> None:
        self.ensure_error: BruteForceProtectionError | None = None
        self.success_error: BruteForceProtectionError | None = None

    async def ensure_not_locked(self, user_id: str) -> None:
        del user_id
        if self.ensure_error is not None:
            raise self.ensure_error

    async def record_failed_password_attempt(self, user_id: str, ip_address=None) -> object:  # type: ignore[no-untyped-def]
        del user_id, ip_address
        return SimpleNamespace(
            locked=False,
            retry_after=None,
            distributed_attack=False,
            attempt_count=1,
        )

    async def record_successful_login(self, user_id: str, ip_address=None, user_agent=None) -> object:  # type: ignore[no-untyped-def]
        del user_id, ip_address, user_agent
        if self.success_error is not None:
            raise self.success_error
        return SimpleNamespace(suspicious=False, metadata={})


class _TokenServiceStub:
    async def issue_token_pair(self, **kwargs: object) -> TokenPair:
        del kwargs
        return TokenPair(access_token="access-token", refresh_token="refresh-token")


class _SessionStub:
    def __init__(self) -> None:
        self.rotate_error: SessionStateError | None = None
        self.revoke_error: SessionStateError | None = None

    async def create_login_session(self, **kwargs: object) -> object:
        return uuid4()

    async def rotate_refresh_session(self, **kwargs: object) -> TokenPair:
        if self.rotate_error is not None:
            raise self.rotate_error
        return TokenPair(access_token="new-access", refresh_token="new-refresh")

    async def revoke_session(self, **kwargs: object) -> None:
        if self.revoke_error is not None:
            raise self.revoke_error


class _M2MStub:
    async def authenticate_client_credentials(self, **kwargs: object) -> object:
        return SimpleNamespace(
            access_token="m2m-token",
            expires_in=300,
            scope="svc:read",
            client_id=kwargs["client_id"],
        )


class _SigningKeyStub:
    async def get_verification_public_keys(self, db_session):  # type: ignore[no-untyped-def]
        del db_session
        return {"kid": "public-key"}


class _JWTStub:
    def __init__(self) -> None:
        self.claims = {
            "sub": "user-1",
            "jti": "access-jti",
            "exp": int((datetime.now(UTC) + timedelta(minutes=5)).timestamp()),
            "type": "access",
        }

    def verify_token(  # type: ignore[no-untyped-def]
        self,
        token: str,
        expected_type: str,
        public_keys_by_kid=None,
        expected_audience=None,
    ):
        del token, expected_type, public_keys_by_kid, expected_audience
        return self.claims


def _db() -> object:
    return object()


@pytest.mark.asyncio
async def test_auth_helpers_and_login_fail_closed_branches(monkeypatch) -> None:
    """Auth helpers and login cover missing-user and brute-force failure wrappers."""
    monkeypatch.setattr(auth_router, "_password_login_requires_verified_email", lambda: True)

    assert auth_router._extract_bearer_token(_request(path="/auth/logout")) is None
    assert (
        auth_router._extract_bearer_token(
            _request(path="/auth/logout", headers={"authorization": "Basic nope"})
        )
        is None
    )

    captured_kwargs: dict[str, object] = {}

    class _LegacyTokenService:
        def issue_token_pair(self, **kwargs: object) -> TokenPair:
            captured_kwargs.update(kwargs)
            return TokenPair(access_token="a", refresh_token="r")

    monkeypatch.setattr("app.routers.auth.inspect.signature", lambda _: None)
    issued = auth_router._issue_token_pair(
        token_service=_LegacyTokenService(),  # type: ignore[arg-type]
        db_session=_db(),  # type: ignore[arg-type]
        user_id="user-1",
        email="user@example.com",
        role="admin",
        email_verified=True,
        email_otp_enabled=True,
        scopes=["svc:read"],
        auth_time=datetime.now(UTC),
    )
    assert issued.access_token == "a"
    assert captured_kwargs == {
        "user_id": "user-1",
        "email": "user@example.com",
        "scopes": ["svc:read"],
    }

    user_service = _UserServiceStub()
    brute_force_service = _BruteForceStub()
    response = await auth_router.login(
        payload=LoginRequest(email="missing@example.com", password="Password123!"),
        request=_request(path="/auth/login"),
        db_session=_db(),  # type: ignore[arg-type]
        user_service=user_service,  # type: ignore[arg-type]
        token_service=_TokenServiceStub(),  # type: ignore[arg-type]
        session_service=_SessionStub(),  # type: ignore[arg-type]
        otp_service=SimpleNamespace(),  # type: ignore[arg-type]
        brute_force_service=brute_force_service,  # type: ignore[arg-type]
        audit_service=_AuditStub(),  # type: ignore[arg-type]
        webhook_service=_WebhookStub(),  # type: ignore[arg-type]
    )
    assert response.status_code == 401

    user_service.user = SimpleNamespace(
        id=uuid4(),
        email="user@example.com",
        password_hash="hashed",
        email_verified=True,
        email_otp_enabled=False,
        role="user",
    )
    brute_force_service.ensure_error = BruteForceProtectionError(
        "locked", "account_locked", 401, headers={"Retry-After": "60"}
    )
    locked = await auth_router.login(
        payload=LoginRequest(email="user@example.com", password="Password123!"),
        request=_request(path="/auth/login"),
        db_session=_db(),  # type: ignore[arg-type]
        user_service=user_service,  # type: ignore[arg-type]
        token_service=_TokenServiceStub(),  # type: ignore[arg-type]
        session_service=_SessionStub(),  # type: ignore[arg-type]
        otp_service=SimpleNamespace(),  # type: ignore[arg-type]
        brute_force_service=brute_force_service,  # type: ignore[arg-type]
        audit_service=_AuditStub(),  # type: ignore[arg-type]
        webhook_service=_WebhookStub(),  # type: ignore[arg-type]
    )
    assert locked.status_code == 401

    brute_force_service.ensure_error = None
    brute_force_service.success_error = BruteForceProtectionError("backend", "session_expired", 503)
    user_service.verify_password_result = True
    login_backend_error = await auth_router.login(
        payload=LoginRequest(email="user@example.com", password="Password123!"),
        request=_request(path="/auth/login"),
        db_session=_db(),  # type: ignore[arg-type]
        user_service=user_service,  # type: ignore[arg-type]
        token_service=_TokenServiceStub(),  # type: ignore[arg-type]
        session_service=_SessionStub(),  # type: ignore[arg-type]
        otp_service=SimpleNamespace(),  # type: ignore[arg-type]
        brute_force_service=brute_force_service,  # type: ignore[arg-type]
        audit_service=_AuditStub(),  # type: ignore[arg-type]
        webhook_service=_WebhookStub(),  # type: ignore[arg-type]
    )
    assert login_backend_error.status_code == 503


@pytest.mark.asyncio
async def test_login_allows_unverified_user_when_policy_disabled(monkeypatch) -> None:
    """Config can explicitly allow password login before email verification."""
    user_service = _UserServiceStub()
    user_service.user = SimpleNamespace(
        id=uuid4(),
        email="user@example.com",
        password_hash="hashed",
        email_verified=False,
        email_otp_enabled=False,
        role="user",
    )
    user_service.verify_password_result = True
    monkeypatch.setattr(auth_router, "_password_login_requires_verified_email", lambda: False)

    response = await auth_router.login(
        payload=LoginRequest(email="user@example.com", password="Password123!"),
        request=_request(path="/auth/login"),
        db_session=_db(),  # type: ignore[arg-type]
        user_service=user_service,  # type: ignore[arg-type]
        token_service=_TokenServiceStub(),  # type: ignore[arg-type]
        session_service=_SessionStub(),  # type: ignore[arg-type]
        otp_service=SimpleNamespace(),  # type: ignore[arg-type]
        brute_force_service=_BruteForceStub(),  # type: ignore[arg-type]
        audit_service=_AuditStub(),  # type: ignore[arg-type]
        webhook_service=_WebhookStub(),  # type: ignore[arg-type]
    )

    assert response.access_token == "access-token"
    assert response.refresh_token == "refresh-token"


@pytest.mark.asyncio
async def test_auth_token_and_logout_routes_cover_form_json_and_session_failures() -> None:
    """Token and logout wrappers cover unsupported grants, bad JSON, refresh failures, and logout failures."""
    audit_service = _AuditStub()
    session_service = _SessionStub()
    m2m_service = _M2MStub()

    bad_grant = await auth_router.token_endpoint(
        request=_request(
            path="/auth/token",
            headers={"content-type": "application/x-www-form-urlencoded"},
            body=b"grant_type=password",
        ),
        db_session=_db(),  # type: ignore[arg-type]
        token_service=_TokenServiceStub(),  # type: ignore[arg-type]
        session_service=session_service,  # type: ignore[arg-type]
        audit_service=audit_service,  # type: ignore[arg-type]
        m2m_service=m2m_service,  # type: ignore[arg-type]
    )
    assert bad_grant.status_code == 400

    missing_client = await auth_router.token_endpoint(
        request=_request(
            path="/auth/token",
            headers={"content-type": "application/x-www-form-urlencoded"},
            body=b"grant_type=client_credentials&client_id=client-1",
        ),
        db_session=_db(),  # type: ignore[arg-type]
        token_service=_TokenServiceStub(),  # type: ignore[arg-type]
        session_service=session_service,  # type: ignore[arg-type]
        audit_service=audit_service,  # type: ignore[arg-type]
        m2m_service=m2m_service,  # type: ignore[arg-type]
    )
    assert missing_client.status_code == 401

    invalid_json = await auth_router.token_endpoint(
        request=_request(
            path="/auth/token",
            headers={"content-type": "application/json"},
            body=b"{bad-json",
        ),
        db_session=_db(),  # type: ignore[arg-type]
        token_service=_TokenServiceStub(),  # type: ignore[arg-type]
        session_service=session_service,  # type: ignore[arg-type]
        audit_service=audit_service,  # type: ignore[arg-type]
        m2m_service=m2m_service,  # type: ignore[arg-type]
    )
    assert invalid_json.status_code == 422

    invalid_payload = await auth_router.token_endpoint(
        request=_request(
            path="/auth/token",
            headers={"content-type": "application/json"},
            body=json.dumps({"wrong": "shape"}).encode("utf-8"),
        ),
        db_session=_db(),  # type: ignore[arg-type]
        token_service=_TokenServiceStub(),  # type: ignore[arg-type]
        session_service=session_service,  # type: ignore[arg-type]
        audit_service=audit_service,  # type: ignore[arg-type]
        m2m_service=m2m_service,  # type: ignore[arg-type]
    )
    assert invalid_payload.status_code == 422

    session_service.rotate_error = SessionStateError("expired", "session_expired", 401)
    refresh_failed = await auth_router.token_endpoint(
        request=_request(
            path="/auth/token",
            headers={"content-type": "application/json"},
            body=json.dumps({"refresh_token": "refresh-token-123456"}).encode("utf-8"),
        ),
        db_session=_db(),  # type: ignore[arg-type]
        token_service=_TokenServiceStub(),  # type: ignore[arg-type]
        session_service=session_service,  # type: ignore[arg-type]
        audit_service=audit_service,  # type: ignore[arg-type]
        m2m_service=m2m_service,  # type: ignore[arg-type]
    )
    assert refresh_failed.status_code == 401

    missing_logout = await auth_router.logout(
        payload=LogoutRequest(refresh_token="refresh-token-123456"),
        request=_request(path="/auth/logout"),
        db_session=_db(),  # type: ignore[arg-type]
        jwt_service=_JWTStub(),  # type: ignore[arg-type]
        signing_key_service=_SigningKeyStub(),  # type: ignore[arg-type]
        session_service=session_service,  # type: ignore[arg-type]
        audit_service=audit_service,  # type: ignore[arg-type]
        webhook_service=_WebhookStub(),  # type: ignore[arg-type]
    )
    assert missing_logout.status_code == 401

    session_service.revoke_error = SessionStateError("expired", "session_expired", 401)
    failed_logout = await auth_router.logout(
        payload=LogoutRequest(refresh_token="refresh-token-123456"),
        request=_request(
            path="/auth/logout",
            headers={"authorization": "Bearer access-token"},
        ),
        db_session=_db(),  # type: ignore[arg-type]
        jwt_service=_JWTStub(),  # type: ignore[arg-type]
        signing_key_service=_SigningKeyStub(),  # type: ignore[arg-type]
        session_service=session_service,  # type: ignore[arg-type]
        audit_service=audit_service,  # type: ignore[arg-type]
        webhook_service=_WebhookStub(),  # type: ignore[arg-type]
    )
    assert failed_logout.status_code == 401
