"""Admin access helper tests for browser-cookie sessions."""

from __future__ import annotations

from uuid import uuid4

import pytest
from fastapi import Request

from app.routers import _admin_access
from app.services.admin_service import AdminServiceError

pytestmark = pytest.mark.usefixtures("browser_session_settings_env")


def _request(
    *,
    method: str,
    path: str,
    headers: dict[str, str] | None = None,
) -> Request:
    """Build a Starlette request for direct helper invocation."""
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


class _AdminServiceStub:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []
        self.claims = {
            "sub": str(uuid4()),
            "email": "admin@example.com",
            "role": "admin",
        }

    async def validate_admin_access_token(self, **kwargs: object) -> dict[str, object]:
        self.calls.append(dict(kwargs))
        return self.claims


@pytest.mark.asyncio
async def test_require_admin_claims_accepts_access_cookie_for_safe_requests() -> None:
    """Cookie-authenticated admin GET requests should validate via the access cookie."""
    admin_service = _AdminServiceStub()
    db_session = object()
    request = _request(
        method="GET",
        path="/admin/users",
        headers={
            "cookie": "auth_access=cookie-admin-token; auth_refresh=refresh-token",
            "x-auth-session-transport": "cookie",
        },
    )

    claims = await _admin_access.require_admin_claims(
        request,
        db_session=db_session,  # type: ignore[arg-type]
        admin_service=admin_service,  # type: ignore[arg-type]
    )

    assert claims["role"] == "admin"
    assert admin_service.calls == [
        {
            "db_session": db_session,
            "token": "cookie-admin-token",
        }
    ]
    assert request.state.user["email"] == "admin@example.com"
    assert request.state.user["role"] == "admin"


@pytest.mark.asyncio
async def test_require_admin_claims_rejects_cookie_authenticated_unsafe_requests_without_csrf() -> (
    None
):
    """Cookie-authenticated admin mutations should require a valid CSRF token."""
    admin_service = _AdminServiceStub()
    request = _request(
        method="DELETE",
        path="/admin/users/123",
        headers={
            "cookie": "auth_access=cookie-admin-token; auth_refresh=refresh-token",
            "x-auth-session-transport": "cookie",
        },
    )

    with pytest.raises(AdminServiceError) as exc_info:
        await _admin_access.require_admin_claims(
            request,
            db_session=object(),  # type: ignore[arg-type]
            admin_service=admin_service,  # type: ignore[arg-type]
        )

    assert exc_info.value.status_code == 403
    assert exc_info.value.code == "invalid_csrf_token"
    assert exc_info.value.detail == "Invalid CSRF token."
    assert admin_service.calls == []
