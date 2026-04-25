"""Additional admin-service edge tests for coverage."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import uuid4

import pytest

from app.core.sessions import SessionStateError
from app.services.admin_service import AdminService, AdminServiceError
from app.services.brute_force_service import BruteForceProtectionError
from app.services.erasure_service import ErasedUserResult
from app.services.user_service import UserServiceError
from app.services.webhook_service import DeletedWebhookEndpoint, WebhookServiceError


class _DBSessionStub:
    def __init__(self, execute_results: list[object] | None = None) -> None:
        self._execute_results = list(execute_results or [])
        self.commit_count = 0
        self.rollback_count = 0

    async def commit(self) -> None:
        self.commit_count += 1

    async def rollback(self) -> None:
        self.rollback_count += 1

    async def execute(self, statement):  # type: ignore[no-untyped-def]
        del statement
        if self._execute_results:
            return self._execute_results.pop(0)
        return self

    def scalar_one_or_none(self):  # type: ignore[no-untyped-def]
        return None

    def scalar_one(self):  # type: ignore[no-untyped-def]
        return 2

    def scalars(self):  # type: ignore[no-untyped-def]
        return self

    def all(self):  # type: ignore[no-untyped-def]
        return []


class _MfaStub:
    async def validate_access_token(self, **kwargs: object) -> dict[str, object]:
        return {"sub": "admin-1", "role": "admin"}

    async def validate_action_token_for_user(self, **kwargs: object) -> bool:
        return False

    async def require_action_token_for_user(self, **kwargs: object) -> None:
        return None

    async def set_user_mfa_state(self, *, db_session, user_id, enabled):  # type: ignore[no-untyped-def]
        del db_session
        return SimpleNamespace(id=user_id, mfa_enabled=enabled)


class _UserServiceStub:
    def __init__(self) -> None:
        self.update_error: UserServiceError | None = None

    async def update_role(self, **kwargs: object) -> object:
        if self.update_error is not None:
            raise self.update_error
        return SimpleNamespace(id=kwargs["user_id"], role=kwargs["new_role"])

    async def delete_user(self, **kwargs: object) -> object:
        return SimpleNamespace(id=kwargs["user_id"])


class _SessionStub:
    def __init__(self) -> None:
        self.error: SessionStateError | None = None

    async def revoke_user_sessions(self, **kwargs: object) -> list[object]:
        if self.error is not None:
            raise self.error
        return [uuid4()]


class _BruteForceStub:
    def __init__(self) -> None:
        self.error: BruteForceProtectionError | None = None

    async def get_lock_status(self, user_id: str) -> tuple[bool, int | None]:
        del user_id
        if self.error is not None:
            raise self.error
        return False, None


class _APIKeyStub:
    async def list_keys_page(self, **kwargs: object) -> object:
        return kwargs

    async def revoke_user_keys(
        self,
        *,
        db_session,
        user_id,
        commit,
    ) -> list[object]:  # type: ignore[no-untyped-def]
        del db_session, user_id, commit
        return []


class _M2MStub:
    async def list_clients_page(self, **kwargs: object) -> object:
        return kwargs


class _WebhookStub:
    def __init__(self) -> None:
        self.error: WebhookServiceError | None = None

    async def list_endpoints_page(self, **kwargs: object) -> object:
        return kwargs

    async def get_endpoint(self, **kwargs: object) -> object:
        if self.error is not None:
            raise self.error
        return object()

    async def list_deliveries_page(self, **kwargs: object) -> object:
        return kwargs

    async def delete_endpoint(self, **kwargs: object) -> DeletedWebhookEndpoint:
        if self.error is not None:
            raise self.error
        return DeletedWebhookEndpoint(id=kwargs["endpoint_id"], abandoned_delivery_ids=[])

    async def update_endpoint(self, **kwargs: object) -> object:
        if self.error is not None:
            raise self.error
        return kwargs


class _AuditStub:
    async def list_events_page(self, **kwargs: object) -> object:
        return kwargs


class _SigningKeyStub:
    async def rotate_signing_key(self, **kwargs: object) -> object:
        return SimpleNamespace(new_kid="new-kid", retiring_kid="old-kid")


class _ErasureStub:
    async def erase_user(self, **kwargs: object) -> ErasedUserResult:
        return ErasedUserResult(
            user_id=kwargs["user_id"],
            anonymized_email="deleted@example.invalid",
            deleted_identity_count=1,
            revoked_session_ids=[],
            revoked_api_key_ids=[],
        )


def _service(
    *,
    user_service: _UserServiceStub | None = None,
    session_service: _SessionStub | None = None,
    brute_force_service: _BruteForceStub | None = None,
    webhook_service: _WebhookStub | None = None,
) -> AdminService:
    return AdminService(
        user_service=user_service or _UserServiceStub(),  # type: ignore[arg-type]
        session_service=session_service or _SessionStub(),  # type: ignore[arg-type]
        mfa_service=_MfaStub(),  # type: ignore[arg-type]
        brute_force_service=brute_force_service or _BruteForceStub(),  # type: ignore[arg-type]
        api_key_service=_APIKeyStub(),  # type: ignore[arg-type]
        m2m_service=_M2MStub(),  # type: ignore[arg-type]
        webhook_service=webhook_service or _WebhookStub(),  # type: ignore[arg-type]
        audit_service=_AuditStub(),  # type: ignore[arg-type]
        signing_key_service=_SigningKeyStub(),  # type: ignore[arg-type]
        erasure_service=_ErasureStub(),  # type: ignore[arg-type]
        enable_retention_purge=False,
        audit_log_retention_days=90,
        session_log_retention_days=30,
    )


@pytest.mark.asyncio
async def test_admin_helpers_cover_invalid_claims_pagination_and_detail_paths() -> None:
    """Admin service covers invalid claims, pagination filters, and detail helpers."""
    service = _service()
    with pytest.raises(AdminServiceError, match="Invalid token"):
        await service.enforce_sensitive_action_gate(
            db_session=_DBSessionStub(),  # type: ignore[arg-type]
            claims={"sub": ""},
            action="role_change",
            action_token=None,
        )
    with pytest.raises(AdminServiceError, match="Invalid token"):
        await service.require_action_token(
            db_session=_DBSessionStub(),  # type: ignore[arg-type]
            claims={"sub": ""},
            action="admin_erase_user",
            action_token=None,
        )

    users = [
        SimpleNamespace(
            id=uuid4(),
            email="locked@example.com",
            role="admin",
            is_active=True,
            email_verified=True,
            mfa_enabled=False,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        ),
        SimpleNamespace(
            id=uuid4(),
            email="active@example.com",
            role="user",
            is_active=True,
            email_verified=True,
            mfa_enabled=False,
            created_at=datetime.now(UTC) - timedelta(seconds=1),
            updated_at=datetime.now(UTC),
        ),
    ]
    db_session = _DBSessionStub(
        [SimpleNamespace(scalars=lambda: SimpleNamespace(all=lambda: users))]
    )  # type: ignore[arg-type]

    async def _summary(user):  # type: ignore[no-untyped-def]
        return SimpleNamespace(
            id=user.id,
            email=user.email,
            role=user.role,
            is_active=user.is_active,
            email_verified=user.email_verified,
            mfa_enabled=user.mfa_enabled,
            locked=user.email == "locked@example.com",
            lock_retry_after=60,
            created_at=user.created_at,
            updated_at=user.updated_at,
        )

    service._build_user_summary = _summary  # type: ignore[assignment]
    page = await service.list_users_page(
        db_session=db_session,  # type: ignore[arg-type]
        role="admin",
        email="example",
        locked=True,
        limit=1,
    )
    assert page.items[0].email == "locked@example.com"

    missing_detail_db = _DBSessionStub([SimpleNamespace(scalar_one_or_none=lambda: None)])
    with pytest.raises(AdminServiceError, match="User not found"):
        await service.get_user_detail(
            db_session=missing_detail_db,  # type: ignore[arg-type]
            user_id=uuid4(),
        )

    detail_user = users[0]
    detail_db = _DBSessionStub(
        [
            SimpleNamespace(scalar_one_or_none=lambda: detail_user),
            SimpleNamespace(scalar_one=lambda: 3),
        ]
    )
    detail = await service.get_user_detail(
        db_session=detail_db,  # type: ignore[arg-type]
        user_id=detail_user.id,
    )
    assert detail.active_session_count == 3


@pytest.mark.asyncio
async def test_list_user_sessions_page_preserves_suspicious_session_fields() -> None:
    """Admin session inventory should preserve suspicious-session flags and reasons."""
    service = _service()
    user_id = uuid4()
    now = datetime.now(UTC)
    session_row = SimpleNamespace(
        id=uuid4(),
        session_id=uuid4(),
        user_id=user_id,
        created_at=now,
        last_seen_at=now,
        expires_at=now + timedelta(hours=1),
        revoked_at=None,
        revoke_reason=None,
        ip_address="203.0.113.10",
        user_agent="Mozilla/5.0 Chrome/120 Windows",
        is_suspicious=True,
        suspicious_reasons=["new_ip", "prior_failures"],
    )
    db_session = _DBSessionStub(
        [SimpleNamespace(scalars=lambda: SimpleNamespace(all=lambda: [session_row]))]
    )

    async def _get_active_user(**kwargs: object) -> object:
        del kwargs
        return SimpleNamespace(id=user_id)

    service._get_active_user = _get_active_user  # type: ignore[assignment]
    page = await service.list_user_sessions_page(
        db_session=db_session,  # type: ignore[arg-type]
        user_id=user_id,
        status="active",
        limit=10,
    )

    assert page.items[0].is_suspicious is True
    assert page.items[0].suspicious_reasons == ["new_ip", "prior_failures"]


@pytest.mark.asyncio
async def test_list_suspicious_sessions_page_returns_enriched_cursor_results() -> None:
    """Global suspicious-session listings should carry user context and cursor metadata."""
    service = _service()
    now = datetime.now(UTC)
    first_session = SimpleNamespace(
        id=uuid4(),
        session_id=uuid4(),
        user_id=uuid4(),
        created_at=now,
        last_seen_at=now,
        expires_at=now + timedelta(hours=1),
        revoked_at=None,
        revoke_reason=None,
        ip_address="203.0.113.20",
        user_agent="Mozilla/5.0 Chrome/120 Windows",
        is_suspicious=True,
        suspicious_reasons=["new_ip"],
    )
    second_session = SimpleNamespace(
        id=uuid4(),
        session_id=uuid4(),
        user_id=uuid4(),
        created_at=now - timedelta(minutes=5),
        last_seen_at=now - timedelta(minutes=1),
        expires_at=now + timedelta(hours=1),
        revoked_at=None,
        revoke_reason=None,
        ip_address="198.51.100.20",
        user_agent="Mozilla/5.0 Safari/17 macOS",
        is_suspicious=True,
        suspicious_reasons=["prior_failures"],
    )
    db_session = _DBSessionStub(
        [
            SimpleNamespace(
                all=lambda: [
                    (first_session, "first@example.com", "user"),
                    (second_session, "second@example.com", "admin"),
                ]
            )
        ]
    )

    page = await service.list_suspicious_sessions_page(
        db_session=db_session,  # type: ignore[arg-type]
        limit=1,
    )

    assert len(page.items) == 1
    assert page.items[0].session_id == first_session.session_id
    assert page.items[0].user_email == "first@example.com"
    assert page.items[0].user_role == "user"
    assert page.items[0].is_suspicious is True
    assert page.items[0].suspicious_reasons == ["new_ip"]
    assert page.has_more is True
    assert page.next_cursor is not None


@pytest.mark.asyncio
async def test_admin_mutation_and_proxy_helpers_cover_error_mapping() -> None:
    """Admin service covers role updates, delete/session/OTP, webhook proxies, and helper branches."""
    user_service = _UserServiceStub()
    user_service.update_error = UserServiceError("bad", "invalid_user", 404)
    service = _service(user_service=user_service)
    with pytest.raises(AdminServiceError):
        await service.update_user_role(
            db_session=_DBSessionStub(),  # type: ignore[arg-type]
            actor_id="admin-1",
            user_id=uuid4(),
            new_role="admin",
            request=object(),
        )

    session_service = _SessionStub()
    db_session = _DBSessionStub()
    deleted = await _service(session_service=session_service).delete_user(
        db_session=db_session,  # type: ignore[arg-type]
        user_id=uuid4(),
    )
    assert deleted.revoked_session_ids
    assert db_session.commit_count == 1

    session_service.error = SessionStateError("expired", "session_expired", 401)
    db_session = _DBSessionStub()
    with pytest.raises(AdminServiceError):
        await _service(session_service=session_service).delete_user(
            db_session=db_session,  # type: ignore[arg-type]
            user_id=uuid4(),
        )
    assert db_session.rollback_count == 1

    webhook_service = _WebhookStub()
    proxied = await _service(webhook_service=webhook_service).list_webhook_deliveries_page(
        db_session=_DBSessionStub(),  # type: ignore[arg-type]
        endpoint_id=uuid4(),
    )
    assert "endpoint_id" in proxied
    webhook_service.error = WebhookServiceError("missing", "invalid_credentials", 404)
    with pytest.raises(AdminServiceError):
        await _service(webhook_service=webhook_service).update_webhook(
            db_session=_DBSessionStub(),  # type: ignore[arg-type]
            endpoint_id=uuid4(),
            name="orders",
        )

    brute_force = _BruteForceStub()
    brute_force.error = BruteForceProtectionError("locked", "account_locked", 401)
    with pytest.raises(AdminServiceError):
        await _service(brute_force_service=brute_force)._get_lock_status("user-1")

    assert _service()._auth_time_is_fresh({"auth_time": "bad"}) is False
    assert _service()._build_user_list_statement(role="admin", email="user@example.com") is not None
    assert _service()._build_user_list_statement(role=None, email="   ") is not None

    user = await _service().set_user_mfa(
        db_session=_DBSessionStub(
            [SimpleNamespace(scalar_one_or_none=lambda: SimpleNamespace(id=uuid4()))]
        ),  # type: ignore[arg-type]
        user_id=uuid4(),
        enabled=True,
    )
    assert user.mfa_enabled is True

    active_user_db = _DBSessionStub([SimpleNamespace(scalar_one_or_none=lambda: None)])
    with pytest.raises(AdminServiceError):
        await _service().revoke_user_sessions(
            db_session=active_user_db,  # type: ignore[arg-type]
            user_id=uuid4(),
        )
