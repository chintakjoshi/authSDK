"""Unit tests for browser-session cookie helpers."""

from __future__ import annotations

import pytest
from starlette.responses import Response

from app.core.browser_sessions import (
    build_cookie_session_response,
    get_browser_session_settings,
    set_access_cookie,
    set_refresh_cookie,
)

pytestmark = pytest.mark.usefixtures("browser_session_settings_env")


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
