"""Shared pytest fixtures for unit tests."""

from __future__ import annotations

import pytest

from app.config import get_settings


@pytest.fixture
def browser_session_settings_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Configure explicit browser-session settings for cookie-transport unit tests."""
    monkeypatch.setenv("BROWSER_SESSIONS__ENABLED", "true")
    monkeypatch.setenv("BROWSER_SESSIONS__SECURE_ONLY", "false")
    monkeypatch.setenv("BROWSER_SESSIONS__ACCESS_COOKIE_NAME", "auth_access")
    monkeypatch.setenv("BROWSER_SESSIONS__REFRESH_COOKIE_NAME", "auth_refresh")
    monkeypatch.setenv("BROWSER_SESSIONS__CSRF_COOKIE_NAME", "auth_csrf")
    monkeypatch.setenv("BROWSER_SESSIONS__ACCESS_COOKIE_PATH", "/")
    monkeypatch.setenv("BROWSER_SESSIONS__REFRESH_COOKIE_PATH", "/_auth")
    monkeypatch.setenv("BROWSER_SESSIONS__CSRF_COOKIE_PATH", "/")
    monkeypatch.setenv("BROWSER_SESSIONS__CSRF_HEADER_NAME", "X-CSRF-Token")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()
