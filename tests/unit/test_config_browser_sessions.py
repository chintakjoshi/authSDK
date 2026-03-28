"""Unit tests for browser-session cookie-prefix validation."""

from __future__ import annotations

import pytest

from app.config import BrowserSessionSettings


def test_browser_sessions_reject_host_prefix_without_secure_only() -> None:
    """__Host- cookies must not be allowed when Secure cookies are disabled."""
    with pytest.raises(ValueError, match="access_cookie_name uses '__Host-'"):
        BrowserSessionSettings(enabled=True, secure_only=False)


def test_browser_sessions_reject_host_prefix_with_non_root_refresh_path() -> None:
    """__Host- refresh cookies must not be scoped to a non-root path."""
    with pytest.raises(ValueError, match="refresh_cookie_path='/'"):
        BrowserSessionSettings(
            enabled=True,
            secure_only=True,
            refresh_cookie_path="/_auth",
        )


def test_browser_sessions_reject_secure_prefix_without_secure_only() -> None:
    """__Secure- cookies still require Secure even without the stricter Host rules."""
    with pytest.raises(ValueError, match="refresh_cookie_name uses '__Secure-'"):
        BrowserSessionSettings(
            enabled=True,
            secure_only=False,
            access_cookie_name="auth_access",
            refresh_cookie_name="__Secure-auth_refresh",
            csrf_cookie_name="auth_csrf",
        )


def test_browser_sessions_accept_local_http_cookie_names() -> None:
    """Local HTTP development should accept non-prefixed cookie names."""
    settings = BrowserSessionSettings(
        enabled=True,
        secure_only=False,
        access_cookie_name="auth_access",
        refresh_cookie_name="auth_refresh",
        csrf_cookie_name="auth_csrf",
        refresh_cookie_path="/_auth",
    )

    assert settings.access_cookie_name == "auth_access"
    assert settings.refresh_cookie_name == "auth_refresh"
    assert settings.csrf_cookie_name == "auth_csrf"
    assert settings.refresh_cookie_path == "/_auth"


def test_browser_sessions_accept_https_host_and_secure_prefix_mix() -> None:
    """HTTPS production can combine host-only access/CSRF cookies with a scoped refresh cookie."""
    settings = BrowserSessionSettings(
        enabled=True,
        secure_only=True,
        access_cookie_name="__Host-auth_access",
        refresh_cookie_name="__Secure-auth_refresh",
        csrf_cookie_name="__Host-auth_csrf",
        refresh_cookie_path="/_auth",
    )

    assert settings.access_cookie_name == "__Host-auth_access"
    assert settings.refresh_cookie_name == "__Secure-auth_refresh"
    assert settings.csrf_cookie_name == "__Host-auth_csrf"
    assert settings.refresh_cookie_path == "/_auth"
