"""Additional unit tests for OAuth service orchestration."""

from __future__ import annotations

import inspect
from dataclasses import dataclass
from typing import Any

import pytest
from redis.exceptions import RedisError

import app.core.callable_compat as callable_compat
from app.core.oauth import OAuthProtocolError
from app.models.user import UserIdentity
from app.services.oauth_service import OAuthService, OAuthServiceError, OAuthStateRecord
from app.services.token_service import TokenPair


class _OAuthClientStub:
    """Configurable OAuth client stub."""

    def __init__(self) -> None:
        self.raise_on_resolve: OAuthProtocolError | None = None
        self.raise_on_authorize: OAuthProtocolError | None = None
        self.raise_on_exchange: OAuthProtocolError | None = None
        self.claims: dict[str, object] = {
            "sub": "provider-user-1",
            "email": "oauth@example.com",
            "email_verified": True,
        }

    def resolve_redirect_uri(self, redirect_uri: str | None) -> str:
        if self.raise_on_resolve is not None:
            raise self.raise_on_resolve
        return redirect_uri or "https://service.local/callback"

    def generate_state(self) -> str:
        return "state-1"

    def generate_nonce(self) -> str:
        return "nonce-1"

    def generate_code_verifier(self) -> str:
        return "verifier-1"

    async def create_google_authorization_url(
        self,
        *,
        state: str,
        nonce: str,
        code_verifier: str,
        redirect_uri: str,
    ) -> str:
        if self.raise_on_authorize is not None:
            raise self.raise_on_authorize
        return (
            f"https://accounts.example/auth?state={state}&nonce={nonce}&redirect_uri={redirect_uri}"
        )

    async def exchange_code_for_tokens(
        self,
        *,
        code: str,
        code_verifier: str,
        redirect_uri: str,
    ) -> dict[str, Any]:
        if self.raise_on_exchange is not None:
            raise self.raise_on_exchange
        return {"id_token": "id-token"}

    async def verify_id_token(self, *, id_token: str, nonce: str) -> dict[str, Any]:
        del id_token, nonce
        return self.claims


class _RedisStub:
    """Redis stub supporting state storage and getdel fallback."""

    def __init__(self) -> None:
        self.values: dict[str, str] = {}
        self.fail_on_setex = False
        self.fail_on_eval = False
        self.deleted: list[str] = []
        self.get_calls: list[str] = []
        self.eval_calls: list[tuple[str, int, tuple[object, ...]]] = []

    async def setex(self, key: str, ttl: int, value: str) -> bool:
        del ttl
        if self.fail_on_setex:
            raise RedisError("redis unavailable")
        self.values[key] = value
        return True

    async def get(self, key: str) -> str | None:
        self.get_calls.append(key)
        return self.values.get(key)

    async def delete(self, key: str) -> int:
        self.deleted.append(key)
        self.values.pop(key, None)
        return 1

    async def eval(self, script: str, numkeys: int, *keys_and_args: object) -> str | None:
        if self.fail_on_eval:
            raise RedisError("redis unavailable")
        self.eval_calls.append((script, numkeys, keys_and_args))
        assert numkeys == 1
        key = str(keys_and_args[0])
        return self.values.pop(key, None)


class _TokenServiceStub:
    """Return deterministic tokens."""

    async def issue_token_pair(self, **kwargs: object) -> TokenPair:
        return TokenPair(access_token="access-token", refresh_token="refresh-token")


class _SessionServiceStub:
    """Capture login-session creation."""

    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    async def create_login_session(self, **kwargs: object) -> str:
        self.calls.append(kwargs)
        return "session-id"


@dataclass
class _UserStub:
    id: str
    email: str
    role: str
    email_verified: bool
    email_otp_enabled: bool = False
    is_active: bool = True
    deleted_at: object | None = None


class _ScalarResult:
    """Scalar result stub mirroring SQLAlchemy's scalar helpers."""

    def __init__(self, value: object) -> None:
        self._value = value

    def scalar_one_or_none(self) -> object:
        return self._value


class _DBSessionStub:
    """DB session stub capturing added rows and execute responses."""

    def __init__(self, execute_results: list[object] | None = None) -> None:
        self._execute_results = list(execute_results or [])
        self.added: list[object] = []
        self.flush_count = 0
        self.rollback_count = 0

    async def execute(self, statement):  # type: ignore[no-untyped-def]
        del statement
        if self._execute_results:
            return _ScalarResult(self._execute_results.pop(0))
        return _ScalarResult(None)

    def add(self, row: object) -> None:
        self.added.append(row)

    async def flush(self) -> None:
        self.flush_count += 1

    async def rollback(self) -> None:
        self.rollback_count += 1


def _build_service(
    oauth_client: _OAuthClientStub | None = None,
    redis_client: _RedisStub | None = None,
    session_service: _SessionServiceStub | None = None,
    allowed_redirect_uris: tuple[str, ...] = (),
) -> OAuthService:
    return OAuthService(
        oauth_client=oauth_client or _OAuthClientStub(),  # type: ignore[arg-type]
        redis_client=redis_client or _RedisStub(),  # type: ignore[arg-type]
        token_service=_TokenServiceStub(),  # type: ignore[arg-type]
        session_service=session_service or _SessionServiceStub(),  # type: ignore[arg-type]
        allowed_redirect_uris=allowed_redirect_uris,
    )


@pytest.mark.asyncio
async def test_build_google_login_url_maps_protocol_errors() -> None:
    """OAuth service forwards protocol failures from redirect validation and authorize URL creation."""
    oauth_client = _OAuthClientStub()
    oauth_client.raise_on_resolve = OAuthProtocolError(
        "Invalid redirect URI.", "invalid_credentials", 400
    )
    service = _build_service(oauth_client=oauth_client)

    with pytest.raises(OAuthServiceError) as exc_info:
        await service.build_google_login_url("https://bad.example/callback")
    assert exc_info.value.status_code == 400

    oauth_client.raise_on_resolve = None
    oauth_client.raise_on_authorize = OAuthProtocolError(
        "OAuth provider unavailable.", "invalid_credentials", 503
    )
    with pytest.raises(OAuthServiceError) as exc_info:
        await service.build_google_login_url(None)
    assert exc_info.value.status_code == 503


@pytest.mark.asyncio
async def test_build_google_login_url_stores_post_auth_redirect_and_requested_audience() -> None:
    """OAuth login initiation should preserve caller redirect and requested audience in state."""
    redis_client = _RedisStub()
    service = _build_service(
        redis_client=redis_client,
        allowed_redirect_uris=("https://app.example.com/post-auth",),
    )

    authorization_url = await service.build_google_login_url(
        "https://app.example.com/post-auth",
        audience="orders-api",
    )
    state_record = await service._consume_state("state-1")

    assert "redirect_uri=https://service.local/callback" in authorization_url
    assert state_record.redirect_uri == "https://service.local/callback"
    assert state_record.return_redirect_uri == "https://app.example.com/post-auth"
    assert state_record.audience == "orders-api"


@pytest.mark.asyncio
async def test_complete_google_callback_rejects_missing_id_token_and_invalid_claims() -> None:
    """Callback completion rejects missing ID tokens and unverified/malformed claims."""
    oauth_client = _OAuthClientStub()
    service = _build_service(oauth_client=oauth_client)

    async def _consume_state(state: str) -> OAuthStateRecord:
        del state
        return OAuthStateRecord(
            nonce="nonce-1",
            code_verifier="verifier-1",
            redirect_uri="https://service.local/callback",
        )

    service._consume_state = _consume_state  # type: ignore[assignment]

    async def _missing_id_token(**kwargs: object) -> dict[str, Any]:
        return {}

    oauth_client.exchange_code_for_tokens = _missing_id_token  # type: ignore[assignment]
    with pytest.raises(OAuthServiceError) as exc_info:
        await service.complete_google_callback(
            db_session=object(),  # type: ignore[arg-type]
            state="state-1",
            code="auth-code",
        )
    assert exc_info.value.code == "invalid_credentials"

    oauth_client.exchange_code_for_tokens = _OAuthClientStub().exchange_code_for_tokens  # type: ignore[assignment]
    oauth_client.claims = {"sub": "", "email": "oauth@example.com", "email_verified": False}
    with pytest.raises(OAuthServiceError) as exc_info:
        await service.complete_google_callback(
            db_session=object(),  # type: ignore[arg-type]
            state="state-1",
            code="auth-code",
        )
    assert exc_info.value.code == "invalid_credentials"


@pytest.mark.asyncio
async def test_complete_google_callback_creates_session_after_successful_upsert() -> None:
    """Successful OAuth callback issues tokens and creates a login session."""
    session_service = _SessionServiceStub()
    service = _build_service(session_service=session_service)

    async def _consume_state(state: str) -> OAuthStateRecord:
        del state
        return OAuthStateRecord(
            nonce="nonce-1",
            code_verifier="verifier-1",
            redirect_uri="https://service.local/callback",
        )

    async def _upsert(**kwargs: object) -> _UserStub:
        return _UserStub(
            id="user-1",
            email="oauth@example.com",
            role="user",
            email_verified=True,
        )

    service._consume_state = _consume_state  # type: ignore[assignment]
    service._upsert_identity_then_resolve_user = _upsert  # type: ignore[assignment]

    result = await service.complete_google_callback(
        db_session=object(),  # type: ignore[arg-type]
        state="state-1",
        code="auth-code",
    )

    assert result.access_token == "access-token"
    assert result.refresh_token == "refresh-token"
    assert result.redirect_uri is None
    assert session_service.calls[0]["email"] == "oauth@example.com"


@pytest.mark.asyncio
async def test_complete_google_callback_preserves_redirect_context_and_requested_audience() -> None:
    """OAuth callback should issue the requested audience and surface redirect context."""
    captured_kwargs: dict[str, object] = {}

    class _AudienceTokenService:
        async def issue_token_pair(
            self,
            *,
            db_session: object,
            user_id: str,
            email: str,
            role: str,
            email_verified: bool,
            email_otp_enabled: bool,
            scopes: list[str],
            audience: str | None = None,
        ) -> TokenPair:
            captured_kwargs.update(
                {
                    "db_session": db_session,
                    "user_id": user_id,
                    "email": email,
                    "role": role,
                    "email_verified": email_verified,
                    "email_otp_enabled": email_otp_enabled,
                    "scopes": scopes,
                    "audience": audience,
                }
            )
            return TokenPair(access_token="access-token", refresh_token="refresh-token")

    service = OAuthService(
        oauth_client=_OAuthClientStub(),  # type: ignore[arg-type]
        redis_client=_RedisStub(),  # type: ignore[arg-type]
        token_service=_AudienceTokenService(),  # type: ignore[arg-type]
        session_service=_SessionServiceStub(),  # type: ignore[arg-type]
        allowed_redirect_uris=("https://app.example.com/post-auth",),
    )

    async def _consume_state(state: str) -> OAuthStateRecord:
        del state
        return OAuthStateRecord(
            nonce="nonce-1",
            code_verifier="verifier-1",
            redirect_uri="https://service.local/callback",
            return_redirect_uri="https://app.example.com/post-auth",
            audience="orders-api",
        )

    async def _upsert(**kwargs: object) -> _UserStub:
        return _UserStub(
            id="user-1",
            email="oauth@example.com",
            role="user",
            email_verified=True,
        )

    service._consume_state = _consume_state  # type: ignore[assignment]
    service._upsert_identity_then_resolve_user = _upsert  # type: ignore[assignment]

    result = await service.complete_google_callback(
        db_session=object(),  # type: ignore[arg-type]
        state="state-1",
        code="auth-code",
    )

    assert result.access_token == "access-token"
    assert result.refresh_token == "refresh-token"
    assert result.redirect_uri == "https://app.example.com/post-auth"
    assert captured_kwargs["audience"] == "orders-api"


@pytest.mark.asyncio
async def test_store_and_consume_state_fail_closed_on_redis_or_bad_payload() -> None:
    """OAuth state storage and one-time consumption fail closed on backend issues."""
    redis_client = _RedisStub()
    service = _build_service(redis_client=redis_client)

    await service._store_state(
        state="state-1",
        record=OAuthStateRecord(
            nonce="nonce-1",
            code_verifier="verifier-1",
            redirect_uri="https://service.local/callback",
        ),
    )
    record = await service._consume_state("state-1")
    assert record.redirect_uri == "https://service.local/callback"
    assert redis_client.get_calls == []
    assert redis_client.deleted == []
    assert len(redis_client.eval_calls) == 1
    assert redis_client.eval_calls[0][1] == 1
    assert redis_client.eval_calls[0][2] == ("oauth_state:state-1",)

    redis_client.fail_on_setex = True
    with pytest.raises(OAuthServiceError) as exc_info:
        await service._store_state(
            state="state-2",
            record=OAuthStateRecord(
                nonce="nonce-2",
                code_verifier="verifier-2",
                redirect_uri="https://service.local/callback",
            ),
        )
    assert exc_info.value.code == "oauth_state_mismatch"

    redis_client.fail_on_setex = False
    redis_client.values["oauth_state:bad"] = "{not-json"
    with pytest.raises(OAuthServiceError) as exc_info:
        await service._consume_state("bad")
    assert exc_info.value.status_code == 401

    redis_client.fail_on_eval = True
    with pytest.raises(OAuthServiceError) as exc_info:
        await service._consume_state("state-3")
    assert exc_info.value.status_code == 503
    assert exc_info.value.code == "oauth_state_mismatch"


def test_state_key_is_stable() -> None:
    """Redis state-key format remains stable for callback lookups."""
    assert OAuthService._state_key("abc123") == "oauth_state:abc123"


def test_issue_token_pair_caches_signature_inspection(monkeypatch: pytest.MonkeyPatch) -> None:
    """OAuth token issuance should reuse cached callable inspection results."""
    captured_kwargs: list[dict[str, object]] = []
    signature_calls = 0
    original_signature = inspect.signature

    class _ModernTokenService:
        def issue_token_pair(
            self,
            *,
            db_session: object,
            user_id: str,
            email: str,
            role: str,
            email_verified: bool,
            email_otp_enabled: bool,
            scopes: list[str],
        ) -> TokenPair:
            captured_kwargs.append(
                {
                    "db_session": db_session,
                    "user_id": user_id,
                    "email": email,
                    "role": role,
                    "email_verified": email_verified,
                    "email_otp_enabled": email_otp_enabled,
                    "scopes": scopes,
                }
            )
            return TokenPair(access_token="access-token", refresh_token="refresh-token")

    def _counting_signature(callable_obj: object) -> inspect.Signature | None:
        nonlocal signature_calls
        signature_calls += 1
        return original_signature(callable_obj)

    callable_compat.clear_callable_parameter_name_cache()
    monkeypatch.setattr(callable_compat.inspect, "signature", _counting_signature)

    service = OAuthService(
        oauth_client=_OAuthClientStub(),  # type: ignore[arg-type]
        redis_client=_RedisStub(),  # type: ignore[arg-type]
        token_service=_ModernTokenService(),  # type: ignore[arg-type]
        session_service=_SessionServiceStub(),  # type: ignore[arg-type]
    )
    first = service._issue_token_pair(
        db_session=object(),  # type: ignore[arg-type]
        user_id="user-1",
        email="oauth@example.com",
        role="admin",
        email_verified=True,
        email_otp_enabled=False,
        scopes=["orders:read"],
    )
    second = service._issue_token_pair(
        db_session=object(),  # type: ignore[arg-type]
        user_id="user-2",
        email="oauth-2@example.com",
        role="user",
        email_verified=False,
        email_otp_enabled=True,
        scopes=["orders:write"],
    )

    assert first.access_token == "access-token"
    assert second.refresh_token == "refresh-token"
    assert signature_calls == 1
    assert captured_kwargs[0]["user_id"] == "user-1"
    assert captured_kwargs[1]["user_id"] == "user-2"


@pytest.mark.asyncio
async def test_issue_token_pair_and_identity_upsert_cover_remaining_paths(monkeypatch) -> None:
    """OAuth service covers legacy token issuers and both identity upsert branches."""
    captured_kwargs: dict[str, object] = {}

    class _LegacyTokenService:
        def issue_token_pair(self, **kwargs: object) -> TokenPair:
            captured_kwargs.update(kwargs)
            return TokenPair(access_token="legacy-access", refresh_token="legacy-refresh")

    service = OAuthService(
        oauth_client=_OAuthClientStub(),  # type: ignore[arg-type]
        redis_client=_RedisStub(),  # type: ignore[arg-type]
        token_service=_LegacyTokenService(),  # type: ignore[arg-type]
        session_service=_SessionServiceStub(),  # type: ignore[arg-type]
    )
    callable_compat.clear_callable_parameter_name_cache()
    monkeypatch.setattr("app.core.callable_compat.inspect.signature", lambda _: None)
    issued = service._issue_token_pair(
        db_session=object(),  # type: ignore[arg-type]
        user_id="user-1",
        email="oauth@example.com",
        role="admin",
        email_verified=True,
        email_otp_enabled=False,
        scopes=["orders:read"],
    )
    assert issued == TokenPair(access_token="legacy-access", refresh_token="legacy-refresh")
    assert captured_kwargs == {
        "user_id": "user-1",
        "email": "oauth@example.com",
        "scopes": ["orders:read"],
    }

    db_session = _DBSessionStub(execute_results=[None])

    async def _missing_user(**kwargs: object) -> None:
        return None

    service._get_user_by_email = _missing_user  # type: ignore[assignment]
    created_user = await service._upsert_identity_then_resolve_user(
        db_session=db_session,  # type: ignore[arg-type]
        provider_user_id="google-user-1",
        email="oauth@example.com",
        email_verified=True,
    )
    assert created_user.email == "oauth@example.com"
    assert isinstance(db_session.added[1], UserIdentity)
    assert db_session.flush_count == 2

    existing_identity = UserIdentity(
        user_id="missing-user",  # type: ignore[arg-type]
        provider="google",
        provider_user_id="google-user-2",
        email="old@example.com",
    )
    db_session = _DBSessionStub(execute_results=[existing_identity])

    async def _missing_by_id(**kwargs: object) -> None:
        return None

    service._get_user_by_id = _missing_by_id  # type: ignore[assignment]
    recreated_user = await service._upsert_identity_then_resolve_user(
        db_session=db_session,  # type: ignore[arg-type]
        provider_user_id="google-user-2",
        email="oauth-new@example.com",
        email_verified=True,
    )
    assert recreated_user.email == "oauth-new@example.com"
    assert existing_identity.user_id == recreated_user.id

    existing_user = _UserStub(
        id="user-3",
        email="stale@example.com",
        role="user",
        email_verified=False,
        email_otp_enabled=False,
    )
    existing_identity = UserIdentity(
        user_id="user-3",  # type: ignore[arg-type]
        provider="google",
        provider_user_id="google-user-3",
        email="stale@example.com",
    )
    db_session = _DBSessionStub(execute_results=[existing_identity])

    async def _existing_by_id(**kwargs: object) -> _UserStub:
        return existing_user

    service._get_user_by_id = _existing_by_id  # type: ignore[assignment]
    resolved_user = await service._upsert_identity_then_resolve_user(
        db_session=db_session,  # type: ignore[arg-type]
        provider_user_id="google-user-3",
        email="fresh@example.com",
        email_verified=True,
    )
    assert resolved_user.email == "fresh@example.com"
    assert resolved_user.email_verified is True
    assert existing_identity.email == "fresh@example.com"


@pytest.mark.asyncio
async def test_identity_upsert_rejects_deleted_or_inactive_oauth_accounts() -> None:
    """OAuth identity upsert fails closed when the mapped or reserved account is deleted."""
    service = _build_service()
    deleted_user = _UserStub(
        id="deleted-user",
        email="oauth@example.com",
        role="user",
        email_verified=True,
        is_active=False,
        deleted_at="deleted",
    )

    async def _missing_user_by_email(**kwargs: object) -> None:
        return None

    async def _deleted_user_by_email(**kwargs: object) -> _UserStub:
        return deleted_user

    service._get_user_by_email = _missing_user_by_email  # type: ignore[assignment]
    service._get_deleted_or_inactive_user_by_email = _deleted_user_by_email  # type: ignore[assignment]
    with pytest.raises(OAuthServiceError) as exc_info:
        await service._upsert_identity_then_resolve_user(
            db_session=_DBSessionStub(),  # type: ignore[arg-type]
            provider_user_id="google-user-1",
            email="oauth@example.com",
            email_verified=True,
        )
    assert exc_info.value.code == "invalid_credentials"

    existing_identity = UserIdentity(
        user_id="deleted-user",  # type: ignore[arg-type]
        provider="google",
        provider_user_id="google-user-2",
        email="oauth@example.com",
    )
    db_session = _DBSessionStub(execute_results=[existing_identity])

    async def _missing_user_by_id(**kwargs: object) -> None:
        return None

    async def _deleted_user_by_id(**kwargs: object) -> _UserStub:
        return deleted_user

    service._get_user_by_id = _missing_user_by_id  # type: ignore[assignment]
    service._get_deleted_or_inactive_user_by_id = _deleted_user_by_id  # type: ignore[assignment]
    with pytest.raises(OAuthServiceError) as exc_info:
        await service._upsert_identity_then_resolve_user(
            db_session=db_session,  # type: ignore[arg-type]
            provider_user_id="google-user-2",
            email="oauth@example.com",
            email_verified=True,
        )
    assert exc_info.value.code == "invalid_credentials"
    assert db_session.added == []


@pytest.mark.asyncio
async def test_complete_google_callback_maps_exchange_and_verify_errors() -> None:
    """OAuth callback wraps token exchange and ID-token verification protocol errors."""
    oauth_client = _OAuthClientStub()
    service = _build_service(oauth_client=oauth_client)

    async def _consume_state(state: str) -> OAuthStateRecord:
        del state
        return OAuthStateRecord(
            nonce="nonce-1",
            code_verifier="verifier-1",
            redirect_uri="https://service.local/callback",
        )

    service._consume_state = _consume_state  # type: ignore[assignment]
    oauth_client.raise_on_exchange = OAuthProtocolError(
        "exchange failed", "invalid_credentials", 401
    )
    with pytest.raises(OAuthServiceError) as exc_info:
        await service.complete_google_callback(
            db_session=object(),  # type: ignore[arg-type]
            state="state-1",
            code="bad-code",
        )
    assert exc_info.value.status_code == 401

    oauth_client.raise_on_exchange = None

    async def _verify_error(*, id_token: str, nonce: str) -> dict[str, Any]:
        del id_token, nonce
        raise OAuthProtocolError("bad id token", "invalid_credentials", 401)

    oauth_client.verify_id_token = _verify_error  # type: ignore[assignment]
    with pytest.raises(OAuthServiceError) as exc_info:
        await service.complete_google_callback(
            db_session=object(),  # type: ignore[arg-type]
            state="state-1",
            code="bad-code",
        )
    assert exc_info.value.code == "invalid_credentials"
