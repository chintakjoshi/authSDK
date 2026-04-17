"""Unit tests for self-service /auth/sessions and /auth/history endpoints."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from app.core.sessions import (
    UserSessionSummary,
    get_session_service,
)
from app.dependencies import get_database_session
from app.routers.self_service import router
from app.services.audit_service import get_audit_service
from app.services.otp_service import AccessTokenValidationResult, OTPServiceError, get_otp_service
from app.services.pagination import CursorPage
from app.services.webhook_service import get_webhook_service

_USER_ID = uuid4()
_CURRENT_SESSION_ID = uuid4()
_OTHER_SESSION_ID = uuid4()
_ACCESS_JTI = "jti-current"


class _JWTServiceStub:
    """JWT stub returning deterministic access-token claims for the test user."""

    def verify_token(
        self,
        token: str,
        expected_type: str,
        public_keys_by_kid=None,
        expected_audience=None,
    ) -> dict[str, Any]:
        del token, public_keys_by_kid, expected_audience
        assert expected_type == "access"
        return {
            "sub": str(_USER_ID),
            "jti": _ACCESS_JTI,
            "exp": int((datetime.now(UTC) + timedelta(minutes=5)).timestamp()),
        }


class _SigningKeyServiceStub:
    async def get_verification_public_keys(self, db_session: Any) -> dict[str, str]:
        del db_session
        return {"kid-1": "public-key"}


class _SessionServiceStub:
    """Session service stub for self-service route behavior tests."""

    def __init__(self) -> None:
        self.revoke_calls: list[dict] = []
        self.revoke_except_calls: list[dict] = []
        self.list_calls: list[dict] = []

    async def resolve_session_id_for_access_jti(self, access_jti: str) -> UUID | None:
        assert access_jti == _ACCESS_JTI
        return _CURRENT_SESSION_ID

    async def list_sessions_for_user(
        self,
        *,
        db_session,
        user_id,
        status,
        cursor,
        limit,
        current_session_id,
    ) -> CursorPage[UserSessionSummary]:
        del db_session, cursor, limit
        self.list_calls.append(
            {
                "user_id": user_id,
                "status": status,
                "current_session_id": current_session_id,
            }
        )
        assert user_id == _USER_ID
        assert status == "active"
        now = datetime.now(UTC)
        items = [
            UserSessionSummary(
                id=uuid4(),
                session_id=_CURRENT_SESSION_ID,
                created_at=now,
                last_seen_at=now,
                expires_at=now + timedelta(hours=1),
                revoked_at=None,
                revoke_reason=None,
                ip_address="203.0.113.1",
                user_agent="Mozilla/5.0 Chrome/120 Windows",
                is_suspicious=True,
                suspicious_reasons=["new_ip", "prior_failures"],
                is_current=(current_session_id == _CURRENT_SESSION_ID),
            ),
            UserSessionSummary(
                id=uuid4(),
                session_id=_OTHER_SESSION_ID,
                created_at=now,
                last_seen_at=None,
                expires_at=now + timedelta(hours=1),
                revoked_at=None,
                revoke_reason=None,
                ip_address=None,
                user_agent=None,
                is_suspicious=False,
                suspicious_reasons=[],
                is_current=False,
            ),
        ]
        return CursorPage(items=items, next_cursor=None, has_more=False)

    async def revoke_one_session(
        self,
        *,
        db_session,
        user_id,
        session_id,
        reason,
    ) -> UUID:
        del db_session
        self.revoke_calls.append({"user_id": user_id, "session_id": session_id, "reason": reason})
        return session_id

    async def revoke_user_sessions_except(
        self,
        *,
        db_session,
        user_id,
        except_session_id,
        reason,
    ) -> list[UUID]:
        del db_session
        self.revoke_except_calls.append(
            {
                "user_id": user_id,
                "except_session_id": except_session_id,
                "reason": reason,
            }
        )
        return [_OTHER_SESSION_ID]


class _OTPServiceStub:
    """OTP stub providing session-aware access-token validation."""

    def __init__(self) -> None:
        self.validation_error: OTPServiceError | None = None

    async def validate_access_token_with_session(
        self,
        *,
        db_session,
        token,
    ) -> AccessTokenValidationResult:
        del db_session
        assert token == "opaque"
        if self.validation_error is not None:
            raise self.validation_error
        return AccessTokenValidationResult(
            claims={
                "sub": str(_USER_ID),
                "jti": _ACCESS_JTI,
                "exp": int((datetime.now(UTC) + timedelta(minutes=5)).timestamp()),
            },
            session_id=_CURRENT_SESSION_ID,
        )


class _AuditServiceStub:
    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    async def record(self, **kwargs: Any) -> None:
        event = {key: value for key, value in kwargs.items() if key not in {"db", "request"}}
        self.events.append(event)

    async def list_events_page(
        self,
        *,
        db_session,
        actor_or_target_id,
        event_types,
        cursor,
        limit,
    ):
        del db_session, cursor, limit
        assert actor_or_target_id == _USER_ID
        assert "user.login.success" in event_types
        row = type(
            "AuditRow",
            (),
            {
                "id": uuid4(),
                "event_type": "user.login.success",
                "actor_id": _USER_ID,
                "actor_type": type("ActorType", (), {"value": "user"})(),
                "target_id": _USER_ID,
                "target_type": "user",
                "ip_address": "203.0.113.2",
                "user_agent": "Mozilla/5.0",
                "correlation_id": uuid4(),
                "success": True,
                "failure_reason": None,
                "event_metadata": {"provider": "password"},
                "created_at": datetime.now(UTC),
            },
        )()
        return CursorPage(items=[row], next_cursor=None, has_more=False)


class _WebhookServiceStub:
    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    async def emit_event(self, *, event_type: str, data: dict[str, Any]) -> None:
        self.events.append({"event_type": event_type, "data": data})


async def _fake_db_dependency():
    yield object()


def _build_app() -> tuple[
    FastAPI,
    _SessionServiceStub,
    _AuditServiceStub,
    _WebhookServiceStub,
    _OTPServiceStub,
]:
    app = FastAPI()
    app.include_router(router)
    session_service = _SessionServiceStub()
    audit_service = _AuditServiceStub()
    webhook_service = _WebhookServiceStub()
    otp_service = _OTPServiceStub()
    app.dependency_overrides[get_database_session] = _fake_db_dependency
    app.dependency_overrides[get_session_service] = lambda: session_service
    app.dependency_overrides[get_otp_service] = lambda: otp_service
    app.dependency_overrides[get_audit_service] = lambda: audit_service
    app.dependency_overrides[get_webhook_service] = lambda: webhook_service
    return app, session_service, audit_service, webhook_service, otp_service


@pytest.mark.asyncio
async def test_list_my_sessions_marks_current_session_and_renders_device_label() -> None:
    """GET /auth/sessions marks the caller's current session and derives device label."""
    app, _session, _audit, _webhook, _otp = _build_app()
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        response = await client.get(
            "/auth/sessions",
            headers={"authorization": "Bearer opaque"},
        )
    assert response.status_code == 200
    body = response.json()
    assert body["has_more"] is False
    items = body["data"]
    assert len(items) == 2
    current = next(item for item in items if item["session_id"] == str(_CURRENT_SESSION_ID))
    assert current["is_current"] is True
    assert current["device_label"] == "Chrome on Windows"
    assert current["is_suspicious"] is True
    assert current["suspicious_reasons"] == ["new_ip", "prior_failures"]
    other = next(item for item in items if item["session_id"] == str(_OTHER_SESSION_ID))
    assert other["is_current"] is False
    assert other["is_suspicious"] is False
    assert other["suspicious_reasons"] == []


@pytest.mark.asyncio
async def test_revoke_my_session_rejects_current_session() -> None:
    """DELETE /auth/sessions/{id} blocks revocation of the caller's current session."""
    app, _session, _audit, _webhook, _otp = _build_app()
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        response = await client.delete(
            f"/auth/sessions/{_CURRENT_SESSION_ID}",
            headers={"authorization": "Bearer opaque"},
        )
    assert response.status_code == 400
    assert response.json()["code"] == "cannot_revoke_current_session"


@pytest.mark.asyncio
async def test_revoke_my_session_propagates_reason_and_emits_events() -> None:
    """DELETE /auth/sessions/{id} uses caller reason and records audit + webhook."""
    app, session_service, audit_service, webhook_service, _otp = _build_app()
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        response = await client.request(
            "DELETE",
            f"/auth/sessions/{_OTHER_SESSION_ID}",
            headers={"authorization": "Bearer opaque"},
            json={"reason": "stolen_laptop"},
        )
    assert response.status_code == 200
    body = response.json()
    assert body["session_id"] == str(_OTHER_SESSION_ID)
    assert body["revoke_reason"] == "stolen_laptop"
    assert session_service.revoke_calls[0]["reason"] == "stolen_laptop"
    assert audit_service.events[0]["event_type"] == "session.revoked"
    assert audit_service.events[0]["metadata"]["reason"] == "stolen_laptop"
    assert webhook_service.events[0]["data"]["reason"] == "stolen_laptop"


@pytest.mark.asyncio
async def test_revoke_my_other_sessions_skips_current_and_defaults_reason() -> None:
    """DELETE /auth/sessions preserves the caller's current session and uses the default reason."""
    app, session_service, _audit, _webhook, _otp = _build_app()
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        response = await client.request(
            "DELETE",
            "/auth/sessions",
            headers={"authorization": "Bearer opaque"},
        )
    assert response.status_code == 200
    body = response.json()
    assert body["revoked_session_ids"] == [str(_OTHER_SESSION_ID)]
    assert body["revoke_reason"] == "self_revoke_others"
    call = session_service.revoke_except_calls[0]
    assert call["except_session_id"] == _CURRENT_SESSION_ID
    assert call["reason"] == "self_revoke_others"


@pytest.mark.asyncio
async def test_list_my_history_returns_filtered_events() -> None:
    """GET /auth/history paginates the caller's filtered audit feed."""
    app, _session, _audit, _webhook, _otp = _build_app()
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        response = await client.get(
            "/auth/history",
            headers={"authorization": "Bearer opaque"},
        )
    assert response.status_code == 200
    body = response.json()
    assert body["has_more"] is False
    assert len(body["data"]) == 1
    assert body["data"][0]["event_type"] == "user.login.success"
    assert body["data"][0]["success"] is True


@pytest.mark.asyncio
async def test_self_service_rejects_missing_bearer() -> None:
    """Self-service endpoints return invalid_token when no bearer header is supplied."""
    app, _session, _audit, _webhook, _otp = _build_app()
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        response = await client.get("/auth/sessions")
    assert response.status_code == 401
    assert response.json()["code"] == "invalid_token"


@pytest.mark.asyncio
async def test_self_service_rejects_stale_access_token_before_listing_sessions() -> None:
    """Self-service session inventory should reject tokens without a valid backing session."""
    app, session_service, _audit, _webhook, otp_service = _build_app()
    otp_service.validation_error = OTPServiceError(
        "Session expired.",
        "session_expired",
        401,
    )

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        response = await client.get(
            "/auth/sessions",
            headers={"authorization": "Bearer opaque"},
        )

    assert response.status_code == 401
    assert response.json()["code"] == "session_expired"
    assert session_service.list_calls == []
