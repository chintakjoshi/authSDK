"""Unit tests for browser-session cookie helpers."""

from __future__ import annotations

import json

import pytest
from fastapi.requests import Request
from starlette.responses import Response

from app.core.browser_sessions import (
    build_cookie_session_redirect_response,
    build_cookie_session_response,
    get_browser_session_settings,
    require_csrf_for_cookie_authenticated_request,
    require_csrf_for_cookie_transport,
    set_access_cookie,
    set_refresh_cookie,
)

pytestmark = pytest.mark.usefixtures("browser_session_settings_env")


def _request(*, method: str = "POST", headers: dict[str, str] | None = None) -> Request:
    """Build a lightweight request for browser-session helper tests."""
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
            "path": "/test",
            "headers": header_list,
            "client": ("127.0.0.1", 12345),
            "scheme": "http",
            "server": ("testserver", 80),
            "query_string": b"",
        },
        receive=_receive,
    )


def _header_for_cookie(response: Response, cookie_name: str) -> str:
    """Return the Set-Cookie header for one named cookie."""
    for header in response.headers.getlist("set-cookie"):
        if header.lower().startswith(f"{cookie_name.lower()}="):
            return header
    raise AssertionError(f"Missing Set-Cookie header for {cookie_name}.")


def test_set_access_cookie_uses_configured_access_token_ttl() -> None:
    """Access cookies should persist for the configured access-token lifetime."""
    response = Response()

    set_access_cookie(response, "access-token")

    settings = get_browser_session_settings()
    header = _header_for_cookie(response, settings.access_cookie_name)

    assert "max-age=900" in header.lower()


def test_set_refresh_cookie_uses_configured_refresh_token_ttl() -> None:
    """Refresh cookies should persist for the configured refresh-token lifetime."""
    response = Response()

    set_refresh_cookie(response, "refresh-token")

    settings = get_browser_session_settings()
    header = _header_for_cookie(response, settings.refresh_cookie_name)

    assert "max-age=604800" in header.lower()


def test_build_cookie_session_response_sets_persistent_auth_cookies() -> None:
    """Cookie-mode auth responses should emit persistent access and refresh cookies."""
    response = build_cookie_session_response(
        access_token="access-token",
        refresh_token="refresh-token",
    )

    settings = get_browser_session_settings()
    access_header = _header_for_cookie(response, settings.access_cookie_name)
    refresh_header = _header_for_cookie(response, settings.refresh_cookie_name)

    assert "max-age=900" in access_header.lower()
    assert "max-age=604800" in refresh_header.lower()


def test_build_cookie_session_redirect_response_sets_auth_and_csrf_cookies() -> None:
    """Federated browser completions should redirect while minting session and CSRF cookies."""
    response = build_cookie_session_redirect_response(
        redirect_url="https://app.example.com/post-auth",
        access_token="access-token",
        refresh_token="refresh-token",
    )

    settings = get_browser_session_settings()
    access_header = _header_for_cookie(response, settings.access_cookie_name)
    refresh_header = _header_for_cookie(response, settings.refresh_cookie_name)
    csrf_header = _header_for_cookie(response, settings.csrf_cookie_name)

    assert response.status_code == 303
    assert response.headers["location"] == "https://app.example.com/post-auth"
    assert "max-age=900" in access_header.lower()
    assert "max-age=604800" in refresh_header.lower()
    assert "httponly" not in csrf_header.lower()


def test_cookie_authenticated_csrf_guard_rejects_conflicting_bearer_and_cookie_auth() -> None:
    """Unsafe authenticated requests should fail closed when bearer and auth cookies coexist."""
    settings = get_browser_session_settings()
    request = _request(
        headers={
            "authorization": "Bearer header-token",
            "cookie": "; ".join(
                [
                    f"{settings.access_cookie_name}=cookie-access-token",
                    f"{settings.refresh_cookie_name}=cookie-refresh-token",
                    f"{settings.csrf_cookie_name}=csrf-token",
                ]
            ),
            settings.csrf_header_name: "csrf-token",
        }
    )

    response = require_csrf_for_cookie_authenticated_request(request)

    assert response is not None
    assert response.status_code == 400
    assert json.loads(response.body) == {
        "detail": "Conflicting authentication transports.",
        "code": "ambiguous_authentication_transport",
    }


def test_cookie_transport_csrf_guard_rejects_conflicting_bearer_and_cookie_transport() -> None:
    """Unsafe cookie-transport requests should reject mixed bearer-plus-cookie credentials."""
    settings = get_browser_session_settings()
    request = _request(
        headers={
            "authorization": "Bearer header-token",
            "cookie": "; ".join(
                [
                    f"{settings.refresh_cookie_name}=cookie-refresh-token",
                    f"{settings.csrf_cookie_name}=csrf-token",
                ]
            ),
            settings.csrf_header_name: "csrf-token",
        }
    )

    response = require_csrf_for_cookie_transport(request)

    assert response is not None
    assert response.status_code == 400
    assert json.loads(response.body) == {
        "detail": "Conflicting authentication transports.",
        "code": "ambiguous_authentication_transport",
    }
