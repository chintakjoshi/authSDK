"""Unit tests for OAuth service state handling."""

from __future__ import annotations

import json
from typing import Any

import pytest

from app.services.oauth_service import OAuthService, OAuthServiceError
from app.services.token_service import TokenPair


class _OAuthClientStub:
    """Stub protocol client for OAuth service tests."""

    def __init__(self) -> None:
        self._counter = 0

    def resolve_redirect_uri(self, redirect_uri: str | None) -> str:
        """Return a fixed valid redirect URI."""
        return redirect_uri or "https://service.local/auth/oauth/google/callback"

    def generate_state(self) -> str:
        """Return deterministic state value."""
        self._counter += 1
        return f"state-{self._counter}"

    def generate_nonce(self) -> str:
        """Return deterministic nonce."""
        return "nonce-value"

    def generate_code_verifier(self) -> str:
        """Return deterministic PKCE verifier."""
        return "code-verifier-value"

    async def create_google_authorization_url(
        self,
        state: str,
        nonce: str,
        code_verifier: str,
        redirect_uri: str,
    ) -> str:
        """Return deterministic authorization URL."""
        return f"https://accounts.google.com/o/oauth2/v2/auth?state={state}&nonce={nonce}"

    async def exchange_code_for_tokens(
        self,
        code: str,
        code_verifier: str,
        redirect_uri: str,
    ) -> dict[str, Any]:
        """Return ID token payload stub."""
        return {"id_token": "stub-id-token"}

    async def verify_id_token(self, id_token: str, nonce: str) -> dict[str, Any]:
        """Return claims with email_verified false to short-circuit DB writes."""
        return {"sub": "google-sub", "email": "user@example.com", "email_verified": False}


class _RedisStub:
    """Async Redis stub supporting state storage operations."""

    def __init__(self) -> None:
        self.values: dict[str, str] = {}
        self.ttls: dict[str, int] = {}

    async def setex(self, key: str, ttl: int, value: str) -> bool:
        """Persist value with TTL."""
        self.values[key] = value
        self.ttls[key] = ttl
        return True

    async def getdel(self, key: str) -> str | None:
        """Atomically return and delete value."""
        value = self.values.pop(key, None)
        self.ttls.pop(key, None)
        return value


class _TokenServiceStub:
    """Stub token service."""

    def issue_token_pair(
        self,
        user_id: str,
        email: str | None = None,
        role: str | None = None,
        scopes: list[str] | None = None,
    ) -> TokenPair:
        """Return deterministic token pair."""
        del user_id, email, role, scopes
        return TokenPair(access_token="access-token", refresh_token="refresh-token")


class _SessionServiceStub:
    """Stub session service."""

    async def create_login_session(
        self,
        db_session: Any,
        user_id: Any,
        email: str,
        role: str,
        email_verified: bool,
        scopes: list[str],
        raw_refresh_token: str,
    ) -> str:
        """Return deterministic session id."""
        del db_session, user_id, email, role, email_verified, scopes, raw_refresh_token
        return "session-id"


@pytest.mark.asyncio
async def test_complete_google_callback_rejects_missing_state() -> None:
    """Missing Redis state returns oauth_state_mismatch."""
    service = OAuthService(
        oauth_client=_OAuthClientStub(),  # type: ignore[arg-type]
        redis_client=_RedisStub(),  # type: ignore[arg-type]
        token_service=_TokenServiceStub(),  # type: ignore[arg-type]
        session_service=_SessionServiceStub(),  # type: ignore[arg-type]
    )

    with pytest.raises(OAuthServiceError) as exc_info:
        await service.complete_google_callback(
            db_session=object(),  # type: ignore[arg-type]
            state="missing-state",
            code="code",
        )

    assert exc_info.value.code == "oauth_state_mismatch"
    assert exc_info.value.status_code == 401


@pytest.mark.asyncio
async def test_complete_google_callback_rejects_replayed_state() -> None:
    """State is one-time use and replay is rejected with oauth_state_mismatch."""
    redis_stub = _RedisStub()
    oauth_client = _OAuthClientStub()
    service = OAuthService(
        oauth_client=oauth_client,  # type: ignore[arg-type]
        redis_client=redis_stub,  # type: ignore[arg-type]
        token_service=_TokenServiceStub(),  # type: ignore[arg-type]
        session_service=_SessionServiceStub(),  # type: ignore[arg-type]
    )

    await service.build_google_login_url(redirect_uri=None)
    state_key = "oauth_state:state-1"
    assert state_key in redis_stub.values
    assert redis_stub.ttls[state_key] == 600
    stored = json.loads(redis_stub.values[state_key])
    assert stored["nonce"] == "nonce-value"

    with pytest.raises(OAuthServiceError) as first_error:
        await service.complete_google_callback(
            db_session=object(),  # type: ignore[arg-type]
            state="state-1",
            code="code",
        )
    assert first_error.value.code == "invalid_credentials"

    with pytest.raises(OAuthServiceError) as second_error:
        await service.complete_google_callback(
            db_session=object(),  # type: ignore[arg-type]
            state="state-1",
            code="code",
        )
    assert second_error.value.code == "oauth_state_mismatch"
    assert second_error.value.status_code == 401
