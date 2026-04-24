"""Additional unit tests for SAML service orchestration."""

from __future__ import annotations

import inspect
from dataclasses import dataclass

import pytest
from redis.exceptions import RedisError

import app.core.callable_compat as callable_compat
from app.core.saml import SamlAssertion, SamlLoginRequest, SamlProtocolError
from app.models.user import UserIdentity
from app.services.saml_service import SamlService, SamlServiceError, SamlStateRecord
from app.services.token_service import TokenPair


class _SamlCoreStub:
    """Configurable SAML core stub."""

    def __init__(self) -> None:
        self.assertion = SamlAssertion(
            provider_user_id="saml-user-1",
            email="saml@example.com",
            email_verified=True,
        )
        self.login_error: SamlProtocolError | None = None
        self.parse_error: SamlProtocolError | None = None
        self.metadata_error: SamlProtocolError | None = None
        self.last_relay_state: str | None = None

    def login_url(
        self,
        request_data: dict[str, str],
        relay_state: str | None,
    ) -> SamlLoginRequest:
        del request_data
        if self.login_error is not None:
            raise self.login_error
        self.last_relay_state = relay_state
        return SamlLoginRequest(
            redirect_url=f"https://idp.example.com/login?RelayState={relay_state}",
            request_id="request-1",
        )

    def parse_assertion(
        self,
        request_data: dict[str, str],
        *,
        expected_request_id: str,
    ) -> SamlAssertion:
        del request_data
        assert expected_request_id == "request-1"
        if self.parse_error is not None:
            raise self.parse_error
        return self.assertion

    def metadata_xml(self) -> str:
        if self.metadata_error is not None:
            raise self.metadata_error
        return "<EntityDescriptor/>"


class _TokenServiceStub:
    """Return deterministic token pairs."""

    async def issue_token_pair(self, **kwargs: object) -> TokenPair:
        return TokenPair(access_token="access-token", refresh_token="refresh-token")


class _SessionServiceStub:
    """Capture login-session creation."""

    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    async def create_login_session(self, **kwargs: object) -> str:
        self.calls.append(kwargs)
        return "session-id"


class _RedisStub:
    """Minimal async Redis stub for SAML request-state tests."""

    def __init__(self) -> None:
        self.values: dict[str, str] = {}

    async def setex(self, key: str, ttl_seconds: int, value: str) -> None:
        del ttl_seconds
        self.values[key] = value

    async def getdel(self, key: str) -> str | None:
        return self.values.pop(key, None)

    async def get(self, key: str) -> str | None:
        return self.values.get(key)

    async def delete(self, key: str) -> None:
        self.values.pop(key, None)


class _RedisFallbackStub:
    """Redis stub exercising the no-GETDEL atomic fallback path."""

    def __init__(self) -> None:
        self.values: dict[str, str] = {}
        self.fail_on_eval = False
        self.get_calls: list[str] = []
        self.deleted: list[str] = []
        self.eval_calls: list[tuple[str, int, tuple[object, ...]]] = []

    async def setex(self, key: str, ttl_seconds: int, value: str) -> None:
        del ttl_seconds
        self.values[key] = value

    async def get(self, key: str) -> str | None:
        self.get_calls.append(key)
        return self.values.get(key)

    async def delete(self, key: str) -> None:
        self.deleted.append(key)
        self.values.pop(key, None)

    async def eval(self, script: str, numkeys: int, *keys_and_args: object) -> str | None:
        if self.fail_on_eval:
            raise RedisError("redis unavailable")
        self.eval_calls.append((script, numkeys, keys_and_args))
        assert numkeys == 1
        key = str(keys_and_args[0])
        return self.values.pop(key, None)


@dataclass
class _UserStub:
    id: str
    email: str
    role: str
    email_verified: bool
    mfa_enabled: bool = False
    is_active: bool = True
    deleted_at: object | None = None


class _ScalarResult:
    """Scalar result stub mirroring SQLAlchemy's scalar helpers."""

    def __init__(self, value: object) -> None:
        self._value = value

    def scalar_one_or_none(self) -> object:
        return self._value


class _DBSessionStub:
    """DB session stub capturing execute results and added rows."""

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


def _service(
    saml_core: _SamlCoreStub | None = None,
    session_service: _SessionServiceStub | None = None,
    allowed_redirect_uris: tuple[str, ...] = (),
) -> SamlService:
    return SamlService(
        saml_core=saml_core or _SamlCoreStub(),  # type: ignore[arg-type]
        token_service=_TokenServiceStub(),  # type: ignore[arg-type]
        session_service=session_service or _SessionServiceStub(),  # type: ignore[arg-type]
        redis_client=_RedisStub(),  # type: ignore[arg-type]
        allowed_redirect_uris=allowed_redirect_uris,
    )


@pytest.mark.asyncio
async def test_create_login_url_and_metadata_map_protocol_failures() -> None:
    """SAML service wraps core protocol failures in service errors."""
    saml_core = _SamlCoreStub()
    saml_core.login_error = SamlProtocolError("bad login", "saml_assertion_invalid", 400)
    service = _service(saml_core=saml_core)

    with pytest.raises(SamlServiceError) as exc_info:
        await service.create_login_url({}, None)
    assert exc_info.value.status_code == 400

    saml_core.login_error = None
    saml_core.metadata_error = SamlProtocolError("bad metadata", "saml_assertion_invalid", 500)
    with pytest.raises(SamlServiceError) as exc_info:
        service.metadata_xml()
    assert exc_info.value.status_code == 500


@pytest.mark.asyncio
async def test_create_login_url_preserves_caller_relay_state_and_requested_audience() -> None:
    """SAML login initiation should retain caller context even when RelayState is internalized."""
    saml_core = _SamlCoreStub()
    service = _service(
        saml_core=saml_core, allowed_redirect_uris=("https://app.example.com/post-auth",)
    )

    redirect_url = await service.create_login_url(
        {},
        "https://app.example.com/post-auth",
        audience="orders-api",
    )
    relay_state = redirect_url.split("RelayState=", 1)[1]
    state_record = await service._consume_state(relay_state)

    assert saml_core.last_relay_state == relay_state
    assert relay_state != "https://app.example.com/post-auth"
    assert state_record.redirect_uri == "https://app.example.com/post-auth"
    assert state_record.relay_state is None
    assert state_record.audience == "orders-api"


@pytest.mark.asyncio
async def test_create_login_url_preserves_opaque_relay_state_when_not_redirect_uri() -> None:
    """SAML login initiation should keep opaque caller relay state for compatibility."""
    saml_core = _SamlCoreStub()
    service = _service(saml_core=saml_core)

    redirect_url = await service.create_login_url({}, "client-flow-state")
    relay_state = redirect_url.split("RelayState=", 1)[1]
    state_record = await service._consume_state(relay_state)

    assert state_record.redirect_uri is None
    assert state_record.relay_state == "client-flow-state"


@pytest.mark.asyncio
async def test_complete_callback_maps_parse_failures_and_creates_session() -> None:
    """SAML callbacks propagate parse failures and create sessions on success."""
    saml_core = _SamlCoreStub()
    saml_core.parse_error = SamlProtocolError("bad assertion", "saml_assertion_invalid", 401)
    service = _service(saml_core=saml_core)

    with pytest.raises(SamlServiceError) as exc_info:
        await service.complete_callback(
            db_session=object(),  # type: ignore[arg-type]
            request_data={"post_data": {"SAMLResponse": "bad", "RelayState": "missing"}},
        )
    assert exc_info.value.status_code == 401

    saml_core.parse_error = None
    session_service = _SessionServiceStub()
    service = _service(saml_core=saml_core, session_service=session_service)
    await service._store_state(  # type: ignore[attr-defined]
        state="relay-state",
        record=SamlStateRecord(request_id="request-1"),
    )

    async def _upsert(**kwargs: object) -> _UserStub:
        return _UserStub(
            id="user-1",
            email="saml@example.com",
            role="user",
            email_verified=True,
        )

    service._upsert_identity_then_resolve_user = _upsert  # type: ignore[assignment]
    result = await service.complete_callback(
        db_session=object(),  # type: ignore[arg-type]
        request_data={"post_data": {"SAMLResponse": "ok", "RelayState": "relay-state"}},
        client_ip="203.0.113.11",
        user_agent="Mozilla/5.0 Firefox/121",
    )

    assert result.access_token == "access-token"
    assert result.refresh_token == "refresh-token"
    assert result.redirect_uri is None
    assert result.relay_state is None
    assert result.user_id == "user-1"
    assert result.session_id == "session-id"
    assert session_service.calls[0]["email"] == "saml@example.com"
    assert session_service.calls[0]["ip_address"] == "203.0.113.11"
    assert session_service.calls[0]["user_agent"] == "Mozilla/5.0 Firefox/121"


@pytest.mark.asyncio
async def test_complete_callback_preserves_redirect_context_and_requested_audience() -> None:
    """SAML callback should issue the requested audience and return caller redirect context."""
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
            mfa_enabled: bool,
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
                    "mfa_enabled": mfa_enabled,
                    "scopes": scopes,
                    "audience": audience,
                }
            )
            return TokenPair(access_token="access-token", refresh_token="refresh-token")

    service = SamlService(
        saml_core=_SamlCoreStub(),  # type: ignore[arg-type]
        token_service=_AudienceTokenService(),  # type: ignore[arg-type]
        session_service=_SessionServiceStub(),  # type: ignore[arg-type]
        redis_client=_RedisStub(),  # type: ignore[arg-type]
        allowed_redirect_uris=("https://app.example.com/post-auth",),
    )

    async def _upsert(**kwargs: object) -> _UserStub:
        return _UserStub(
            id="user-1",
            email="saml@example.com",
            role="user",
            email_verified=True,
        )

    service._upsert_identity_then_resolve_user = _upsert  # type: ignore[assignment]
    await service._store_state(  # type: ignore[attr-defined]
        state="relay-state",
        record=SamlStateRecord(
            request_id="request-1",
            redirect_uri="https://app.example.com/post-auth",
            relay_state="client-flow-state",
            audience="orders-api",
        ),
    )

    result = await service.complete_callback(
        db_session=object(),  # type: ignore[arg-type]
        request_data={"post_data": {"SAMLResponse": "ok", "RelayState": "relay-state"}},
    )

    assert result.access_token == "access-token"
    assert result.refresh_token == "refresh-token"
    assert result.redirect_uri == "https://app.example.com/post-auth"
    assert result.relay_state == "client-flow-state"
    assert captured_kwargs["audience"] == "orders-api"


@pytest.mark.asyncio
async def test_store_and_consume_state_uses_atomic_eval_fallback_without_getdel() -> None:
    """SAML state fallback should use one atomic Redis operation when GETDEL is unavailable."""
    redis_client = _RedisFallbackStub()
    service = SamlService(
        saml_core=_SamlCoreStub(),  # type: ignore[arg-type]
        token_service=_TokenServiceStub(),  # type: ignore[arg-type]
        session_service=_SessionServiceStub(),  # type: ignore[arg-type]
        redis_client=redis_client,  # type: ignore[arg-type]
    )

    await service._store_state(  # type: ignore[attr-defined]
        state="relay-state",
        record=SamlStateRecord(request_id="request-1"),
    )
    record = await service._consume_state("relay-state")
    assert record.request_id == "request-1"
    assert redis_client.get_calls == []
    assert redis_client.deleted == []
    assert len(redis_client.eval_calls) == 1
    assert redis_client.eval_calls[0][1] == 1
    assert redis_client.eval_calls[0][2] == ("saml_state:relay-state",)

    with pytest.raises(SamlServiceError) as exc_info:
        await service._consume_state("relay-state")
    assert exc_info.value.status_code == 401

    redis_client.values["saml_state:bad"] = "{not-json"
    with pytest.raises(SamlServiceError) as exc_info:
        await service._consume_state("bad")
    assert exc_info.value.status_code == 401

    redis_client.fail_on_eval = True
    with pytest.raises(SamlServiceError) as exc_info:
        await service._consume_state("missing")
    assert exc_info.value.status_code == 503
    assert exc_info.value.code == "saml_assertion_invalid"


def test_issue_token_pair_caches_signature_inspection(monkeypatch: pytest.MonkeyPatch) -> None:
    """SAML token issuance should reuse cached callable inspection results."""
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
            mfa_enabled: bool,
            scopes: list[str],
        ) -> TokenPair:
            captured_kwargs.append(
                {
                    "db_session": db_session,
                    "user_id": user_id,
                    "email": email,
                    "role": role,
                    "email_verified": email_verified,
                    "mfa_enabled": mfa_enabled,
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

    service = SamlService(
        saml_core=_SamlCoreStub(),  # type: ignore[arg-type]
        token_service=_ModernTokenService(),  # type: ignore[arg-type]
        session_service=_SessionServiceStub(),  # type: ignore[arg-type]
        redis_client=_RedisStub(),  # type: ignore[arg-type]
    )
    first = service._issue_token_pair(
        db_session=object(),  # type: ignore[arg-type]
        user_id="user-1",
        email="saml@example.com",
        role="admin",
        email_verified=True,
        mfa_enabled=False,
        scopes=["orders:read"],
    )
    second = service._issue_token_pair(
        db_session=object(),  # type: ignore[arg-type]
        user_id="user-2",
        email="saml-2@example.com",
        role="user",
        email_verified=False,
        mfa_enabled=True,
        scopes=["orders:write"],
    )

    assert first.access_token == "access-token"
    assert second.refresh_token == "refresh-token"
    assert signature_calls == 1
    assert captured_kwargs[0]["user_id"] == "user-1"
    assert captured_kwargs[1]["user_id"] == "user-2"


@pytest.mark.asyncio
async def test_issue_token_pair_and_identity_upsert_cover_remaining_paths(monkeypatch) -> None:
    """SAML service covers legacy token issuers and both user-identity upsert branches."""
    captured_kwargs: dict[str, object] = {}

    class _LegacyTokenService:
        def issue_token_pair(self, **kwargs: object) -> TokenPair:
            captured_kwargs.update(kwargs)
            return TokenPair(access_token="legacy-access", refresh_token="legacy-refresh")

    service = SamlService(
        saml_core=_SamlCoreStub(),  # type: ignore[arg-type]
        token_service=_LegacyTokenService(),  # type: ignore[arg-type]
        session_service=_SessionServiceStub(),  # type: ignore[arg-type]
        redis_client=_RedisStub(),  # type: ignore[arg-type]
    )
    callable_compat.clear_callable_parameter_name_cache()
    monkeypatch.setattr("app.core.callable_compat.inspect.signature", lambda _: None)
    issued = service._issue_token_pair(
        db_session=object(),  # type: ignore[arg-type]
        user_id="user-1",
        email="saml@example.com",
        role="admin",
        email_verified=True,
        mfa_enabled=False,
        scopes=["orders:read"],
    )
    assert issued == TokenPair(access_token="legacy-access", refresh_token="legacy-refresh")
    assert captured_kwargs == {
        "user_id": "user-1",
        "email": "saml@example.com",
        "scopes": ["orders:read"],
    }

    db_session = _DBSessionStub(execute_results=[None])

    async def _missing_user(**kwargs: object) -> None:
        return None

    service._get_user_by_email = _missing_user  # type: ignore[assignment]
    created_user = await service._upsert_identity_then_resolve_user(
        db_session=db_session,  # type: ignore[arg-type]
        provider_user_id="saml-user-1",
        email="saml@example.com",
        email_verified=True,
    )
    assert created_user.email == "saml@example.com"
    assert isinstance(db_session.added[1], UserIdentity)
    assert db_session.flush_count == 2

    existing_identity = UserIdentity(
        user_id="missing-user",  # type: ignore[arg-type]
        provider="saml",
        provider_user_id="saml-user-2",
        email="old@example.com",
    )
    db_session = _DBSessionStub(execute_results=[existing_identity])

    async def _missing_by_id(**kwargs: object) -> None:
        return None

    service._get_user_by_id = _missing_by_id  # type: ignore[assignment]
    recreated_user = await service._upsert_identity_then_resolve_user(
        db_session=db_session,  # type: ignore[arg-type]
        provider_user_id="saml-user-2",
        email="saml-new@example.com",
        email_verified=True,
    )
    assert recreated_user.email == "saml-new@example.com"
    assert existing_identity.user_id == recreated_user.id

    existing_user = _UserStub(
        id="user-3",
        email="stale@example.com",
        role="user",
        email_verified=False,
        mfa_enabled=False,
    )
    existing_identity = UserIdentity(
        user_id="user-3",  # type: ignore[arg-type]
        provider="saml",
        provider_user_id="saml-user-3",
        email="stale@example.com",
    )
    db_session = _DBSessionStub(execute_results=[existing_identity])

    async def _existing_by_id(**kwargs: object) -> _UserStub:
        return existing_user

    service._get_user_by_id = _existing_by_id  # type: ignore[assignment]
    resolved_user = await service._upsert_identity_then_resolve_user(
        db_session=db_session,  # type: ignore[arg-type]
        provider_user_id="saml-user-3",
        email="fresh@example.com",
        email_verified=True,
    )
    assert resolved_user.email == "fresh@example.com"
    assert resolved_user.email_verified is True
    assert existing_identity.email == "fresh@example.com"


@pytest.mark.asyncio
async def test_identity_upsert_rejects_deleted_or_inactive_saml_accounts() -> None:
    """SAML identity upsert fails closed when the mapped or reserved account is deleted."""
    service = _service()
    deleted_user = _UserStub(
        id="deleted-user",
        email="saml@example.com",
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
    with pytest.raises(SamlServiceError) as exc_info:
        await service._upsert_identity_then_resolve_user(
            db_session=_DBSessionStub(),  # type: ignore[arg-type]
            provider_user_id="saml-user-1",
            email="saml@example.com",
            email_verified=True,
        )
    assert exc_info.value.code == "invalid_credentials"

    existing_identity = UserIdentity(
        user_id="deleted-user",  # type: ignore[arg-type]
        provider="saml",
        provider_user_id="saml-user-2",
        email="saml@example.com",
    )
    db_session = _DBSessionStub(execute_results=[existing_identity])

    async def _missing_user_by_id(**kwargs: object) -> None:
        return None

    async def _deleted_user_by_id(**kwargs: object) -> _UserStub:
        return deleted_user

    service._get_user_by_id = _missing_user_by_id  # type: ignore[assignment]
    service._get_deleted_or_inactive_user_by_id = _deleted_user_by_id  # type: ignore[assignment]
    with pytest.raises(SamlServiceError) as exc_info:
        await service._upsert_identity_then_resolve_user(
            db_session=db_session,  # type: ignore[arg-type]
            provider_user_id="saml-user-2",
            email="saml@example.com",
            email_verified=True,
        )
    assert exc_info.value.code == "invalid_credentials"
    assert db_session.added == []


@pytest.mark.asyncio
async def test_identity_upsert_rejects_unverified_saml_link_to_existing_user() -> None:
    """New SAML identities cannot attach to an existing user without verified email."""
    service = _service()
    existing_user = _UserStub(
        id="user-1",
        email="victim@example.com",
        role="user",
        email_verified=True,
    )
    db_session = _DBSessionStub(execute_results=[None])

    async def _existing_user_by_email(**kwargs: object) -> _UserStub:
        return existing_user

    service._get_user_by_email = _existing_user_by_email  # type: ignore[assignment]

    with pytest.raises(SamlServiceError) as exc_info:
        await service._upsert_identity_then_resolve_user(
            db_session=db_session,  # type: ignore[arg-type]
            provider_user_id="saml-user-1",
            email="victim@example.com",
            email_verified=False,
        )

    assert exc_info.value.code == "invalid_credentials"
    assert db_session.added == []
    assert db_session.flush_count == 0
