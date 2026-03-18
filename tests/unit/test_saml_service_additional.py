"""Additional unit tests for SAML service orchestration."""

from __future__ import annotations

from dataclasses import dataclass

import pytest

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

    def login_url(
        self,
        request_data: dict[str, str],
        relay_state: str | None,
    ) -> SamlLoginRequest:
        del request_data, relay_state
        if self.login_error is not None:
            raise self.login_error
        return SamlLoginRequest(
            redirect_url="https://idp.example.com/login",
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


@dataclass
class _UserStub:
    id: str
    email: str
    role: str
    email_verified: bool
    email_otp_enabled: bool = False


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

    async def execute(self, statement):  # type: ignore[no-untyped-def]
        del statement
        if self._execute_results:
            return _ScalarResult(self._execute_results.pop(0))
        return _ScalarResult(None)

    def add(self, row: object) -> None:
        self.added.append(row)

    async def flush(self) -> None:
        self.flush_count += 1


def _service(
    saml_core: _SamlCoreStub | None = None,
    session_service: _SessionServiceStub | None = None,
) -> SamlService:
    return SamlService(
        saml_core=saml_core or _SamlCoreStub(),  # type: ignore[arg-type]
        token_service=_TokenServiceStub(),  # type: ignore[arg-type]
        session_service=session_service or _SessionServiceStub(),  # type: ignore[arg-type]
        redis_client=_RedisStub(),  # type: ignore[arg-type]
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
    )

    assert result == TokenPair(access_token="access-token", refresh_token="refresh-token")
    assert session_service.calls[0]["email"] == "saml@example.com"


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
    monkeypatch.setattr("app.services.saml_service.inspect.signature", lambda _: None)
    issued = service._issue_token_pair(
        db_session=object(),  # type: ignore[arg-type]
        user_id="user-1",
        email="saml@example.com",
        role="admin",
        email_verified=True,
        email_otp_enabled=False,
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
        email_otp_enabled=False,
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
