"""Auth router tests for browser-session support."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi.requests import Request
from starlette.responses import Response

from app.routers import auth as auth_router
from app.schemas.token import LogoutRequest
from app.schemas.user import LoginRequest
from app.services.token_service import TokenPair


def _request(
    *,
    method: str,
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
    async def record(self, **kwargs: object) -> None:
        del kwargs


class _WebhookStub:
    async def emit_event(self, *, event_type: str, data: dict[str, object]) -> None:
        del event_type, data


class _UserServiceStub:
    def __init__(self) -> None:
        self.user = SimpleNamespace(
            id=uuid4(),
            email="user@example.com",
            password_hash="hashed",
            email_verified=True,
            email_otp_enabled=False,
            role="user",
        )

    async def get_user_by_email(self, **kwargs: object) -> object | None:
        del kwargs
        return self.user

    def dummy_verify(self) -> None:
        return None

    def verify_password(self, **kwargs: object) -> bool:
        del kwargs
        return True


class _BruteForceStub:
    async def ensure_not_locked(self, user_id: str) -> None:
        del user_id

    async def record_failed_password_attempt(self, user_id: str, ip_address=None) -> object:  # type: ignore[no-untyped-def]
        del user_id, ip_address
        return SimpleNamespace(
            locked=False,
            retry_after=None,
            distributed_attack=False,
            attempt_count=0,
        )

    async def record_successful_login(self, user_id: str, ip_address=None, user_agent=None) -> object:  # type: ignore[no-untyped-def]
        del user_id, ip_address, user_agent
        return SimpleNamespace(suspicious=False, metadata={})


class _TokenServiceStub:
    async def issue_token_pair(self, **kwargs: object) -> TokenPair:
        del kwargs
        return TokenPair(access_token="issued-access-token", refresh_token="issued-refresh-token")


class _SessionStub:
    async def create_login_session(self, **kwargs: object) -> object:
        del kwargs
        return uuid4()

    async def rotate_refresh_session(self, **kwargs: object) -> TokenPair:
        del kwargs
        return TokenPair(
            access_token="rotated-access-token",
            refresh_token="rotated-refresh-token",
        )

    async def revoke_session(self, **kwargs: object) -> None:
        del kwargs


class _OTPStub:
    async def validate_access_token(self, **kwargs: object) -> None:
        del kwargs


class _M2MStub:
    async def authenticate_client_credentials(self, **kwargs: object) -> object:
        del kwargs
        raise AssertionError("client credentials branch should not run in cookie refresh test")


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


def _cookie_headers(
    *cookies: str,
    csrf_token: str = "csrf-token",
    include_transport_header: bool = True,
) -> dict[str, str]:
    """Build request headers for cookie-mode browser-session tests."""
    cookie_value = "; ".join([f"__Host-auth_csrf={csrf_token}", *cookies])
    headers = {
        "x-csrf-token": csrf_token,
        "cookie": cookie_value,
    }
    if include_transport_header:
        headers["x-auth-session-transport"] = "cookie"
    return headers


@pytest.mark.asyncio
async def test_login_cookie_transport_sets_session_cookies_and_omits_raw_tokens(
    monkeypatch,
) -> None:
    """Cookie-mode login should set cookies instead of returning token pairs."""
    monkeypatch.setattr(auth_router, "_password_login_requires_verified_email", lambda: False)

    response = await auth_router.login(
        payload=LoginRequest(email="user@example.com", password="Password123!"),
        request=_request(
            method="POST",
            path="/auth/login",
            headers=_cookie_headers(),
        ),
        db_session=_db(),  # type: ignore[arg-type]
        user_service=_UserServiceStub(),  # type: ignore[arg-type]
        token_service=_TokenServiceStub(),  # type: ignore[arg-type]
        session_service=_SessionStub(),  # type: ignore[arg-type]
        otp_service=_OTPStub(),  # type: ignore[arg-type]
        brute_force_service=_BruteForceStub(),  # type: ignore[arg-type]
        audit_service=_AuditStub(),  # type: ignore[arg-type]
        webhook_service=_WebhookStub(),  # type: ignore[arg-type]
    )

    assert isinstance(response, Response)
    assert response.status_code == 200
    assert json.loads(response.body) == {
        "authenticated": True,
        "session_transport": "cookie",
    }
    set_cookie_headers = response.headers.getlist("set-cookie")
    assert any("httponly" in header.lower() for header in set_cookie_headers)
    assert any("samesite" in header.lower() for header in set_cookie_headers)


@pytest.mark.asyncio
async def test_login_infers_cookie_transport_from_browser_session_context_without_header(
    monkeypatch,
) -> None:
    """Login should default to cookie transport when browser-session context is present."""
    monkeypatch.setattr(auth_router, "_password_login_requires_verified_email", lambda: False)

    response = await auth_router.login(
        payload=LoginRequest(email="user@example.com", password="Password123!"),
        request=_request(
            method="POST",
            path="/auth/login",
            headers=_cookie_headers(include_transport_header=False),
        ),
        db_session=_db(),  # type: ignore[arg-type]
        user_service=_UserServiceStub(),  # type: ignore[arg-type]
        token_service=_TokenServiceStub(),  # type: ignore[arg-type]
        session_service=_SessionStub(),  # type: ignore[arg-type]
        otp_service=_OTPStub(),  # type: ignore[arg-type]
        brute_force_service=_BruteForceStub(),  # type: ignore[arg-type]
        audit_service=_AuditStub(),  # type: ignore[arg-type]
        webhook_service=_WebhookStub(),  # type: ignore[arg-type]
    )

    assert isinstance(response, Response)
    assert response.status_code == 200
    assert json.loads(response.body) == {
        "authenticated": True,
        "session_transport": "cookie",
    }
    set_cookie_headers = response.headers.getlist("set-cookie")
    assert any("__host-auth_access=" in header.lower() for header in set_cookie_headers)
    assert any("__host-auth_refresh=" in header.lower() for header in set_cookie_headers)


@pytest.mark.asyncio
async def test_login_explicit_token_transport_overrides_browser_session_context(
    monkeypatch,
) -> None:
    """Explicit token transport should preserve legacy token-pair responses."""
    monkeypatch.setattr(auth_router, "_password_login_requires_verified_email", lambda: False)

    response = await auth_router.login(
        payload=LoginRequest(email="user@example.com", password="Password123!"),
        request=_request(
            method="POST",
            path="/auth/login",
            headers={
                "x-auth-session-transport": "token",
                **_cookie_headers(include_transport_header=False),
            },
        ),
        db_session=_db(),  # type: ignore[arg-type]
        user_service=_UserServiceStub(),  # type: ignore[arg-type]
        token_service=_TokenServiceStub(),  # type: ignore[arg-type]
        session_service=_SessionStub(),  # type: ignore[arg-type]
        otp_service=_OTPStub(),  # type: ignore[arg-type]
        brute_force_service=_BruteForceStub(),  # type: ignore[arg-type]
        audit_service=_AuditStub(),  # type: ignore[arg-type]
        webhook_service=_WebhookStub(),  # type: ignore[arg-type]
    )

    assert response.access_token == "issued-access-token"
    assert response.refresh_token == "issued-refresh-token"


@pytest.mark.asyncio
async def test_refresh_cookie_transport_uses_refresh_cookie_and_rotates_session_cookies() -> None:
    """Cookie-mode refresh should rotate cookies without reading raw tokens from JSON."""
    response = await auth_router.token_endpoint(
        request=_request(
            method="POST",
            path="/auth/token",
            headers=_cookie_headers("__Host-auth_refresh=refresh-cookie-token"),
        ),
        db_session=_db(),  # type: ignore[arg-type]
        token_service=_TokenServiceStub(),  # type: ignore[arg-type]
        session_service=_SessionStub(),  # type: ignore[arg-type]
        m2m_service=_M2MStub(),  # type: ignore[arg-type]
        audit_service=_AuditStub(),  # type: ignore[arg-type]
    )

    assert isinstance(response, Response)
    assert response.status_code == 200
    assert json.loads(response.body) == {
        "authenticated": True,
        "session_transport": "cookie",
    }
    set_cookie_headers = response.headers.getlist("set-cookie")
    assert any("__host-auth_access=" in header.lower() for header in set_cookie_headers)
    assert any("__host-auth_refresh=" in header.lower() for header in set_cookie_headers)


@pytest.mark.asyncio
async def test_refresh_infers_cookie_transport_from_browser_session_context_without_header() -> (
    None
):
    """Refresh should default to cookie transport when refresh-session cookies are present."""
    response = await auth_router.token_endpoint(
        request=_request(
            method="POST",
            path="/auth/token",
            headers=_cookie_headers(
                "__Host-auth_refresh=refresh-cookie-token",
                include_transport_header=False,
            ),
        ),
        db_session=_db(),  # type: ignore[arg-type]
        token_service=_TokenServiceStub(),  # type: ignore[arg-type]
        session_service=_SessionStub(),  # type: ignore[arg-type]
        m2m_service=_M2MStub(),  # type: ignore[arg-type]
        audit_service=_AuditStub(),  # type: ignore[arg-type]
    )

    assert isinstance(response, Response)
    assert response.status_code == 200
    assert json.loads(response.body) == {
        "authenticated": True,
        "session_transport": "cookie",
    }
    set_cookie_headers = response.headers.getlist("set-cookie")
    assert any("__host-auth_access=" in header.lower() for header in set_cookie_headers)
    assert any("__host-auth_refresh=" in header.lower() for header in set_cookie_headers)


@pytest.mark.asyncio
async def test_logout_cookie_transport_uses_cookies_and_clears_session_cookies() -> None:
    """Cookie-mode logout should not require bearer auth or refresh body tokens."""
    response = await auth_router.logout(
        payload=LogoutRequest(refresh_token="legacy-refresh-token-placeholder"),
        request=_request(
            method="POST",
            path="/auth/logout",
            headers=_cookie_headers(
                "__Host-auth_access=access-cookie-token",
                "__Host-auth_refresh=refresh-cookie-token",
            ),
        ),
        db_session=_db(),  # type: ignore[arg-type]
        jwt_service=_JWTStub(),  # type: ignore[arg-type]
        signing_key_service=_SigningKeyStub(),  # type: ignore[arg-type]
        session_service=_SessionStub(),  # type: ignore[arg-type]
        audit_service=_AuditStub(),  # type: ignore[arg-type]
        webhook_service=_WebhookStub(),  # type: ignore[arg-type]
    )

    assert isinstance(response, Response)
    assert response.status_code == 204
    set_cookie_headers = response.headers.getlist("set-cookie")
    assert any("__host-auth_access=" in header.lower() for header in set_cookie_headers)
    assert any("__host-auth_refresh=" in header.lower() for header in set_cookie_headers)
    assert any(
        "max-age=0" in header.lower() or "expires=" in header.lower()
        for header in set_cookie_headers
    )


@pytest.mark.asyncio
async def test_logout_infers_cookie_transport_from_browser_session_context_without_header() -> None:
    """Logout should default to cookie transport when session cookies are present."""
    response = await auth_router.logout(
        payload=LogoutRequest(refresh_token="legacy-refresh-token-placeholder"),
        request=_request(
            method="POST",
            path="/auth/logout",
            headers=_cookie_headers(
                "__Host-auth_access=access-cookie-token",
                "__Host-auth_refresh=refresh-cookie-token",
                include_transport_header=False,
            ),
        ),
        db_session=_db(),  # type: ignore[arg-type]
        jwt_service=_JWTStub(),  # type: ignore[arg-type]
        signing_key_service=_SigningKeyStub(),  # type: ignore[arg-type]
        session_service=_SessionStub(),  # type: ignore[arg-type]
        audit_service=_AuditStub(),  # type: ignore[arg-type]
        webhook_service=_WebhookStub(),  # type: ignore[arg-type]
    )

    assert isinstance(response, Response)
    assert response.status_code == 204
    set_cookie_headers = response.headers.getlist("set-cookie")
    assert any("__host-auth_access=" in header.lower() for header in set_cookie_headers)
    assert any("__host-auth_refresh=" in header.lower() for header in set_cookie_headers)
    assert any(
        "max-age=0" in header.lower() or "expires=" in header.lower()
        for header in set_cookie_headers
    )


@pytest.mark.asyncio
async def test_csrf_endpoint_sets_cookie_and_returns_token() -> None:
    """Browser-session support needs a dedicated CSRF bootstrap endpoint."""
    response = await auth_router.csrf()

    assert isinstance(response, Response)
    assert response.status_code == 200
    payload = json.loads(response.body)
    assert payload["csrf_token"]
    set_cookie_headers = response.headers.getlist("set-cookie")
    assert any("__host-auth_csrf=" in header.lower() for header in set_cookie_headers)
