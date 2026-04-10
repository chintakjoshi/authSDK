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


class _OTPStub:
    async def validate_access_token(self, **kwargs: object) -> dict[str, object]:
        return {"sub": "admin-1", "role": "admin"}

    async def validate_action_token_for_user(self, **kwargs: object) -> bool:
        return False

    async def require_action_token_for_user(self, **kwargs: object) -> None:
        return None

    async def enable_email_otp(self, **kwargs: object) -> object:
        return SimpleNamespace(id=kwargs["user_id"], email_otp_enabled=True)

    async def disable_email_otp(self, **kwargs: object) -> object:
        return SimpleNamespace(id=kwargs["user_id"], email_otp_enabled=False)


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
        otp_service=_OTPStub(),  # type: ignore[arg-type]
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
            email_otp_enabled=False,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        ),
        SimpleNamespace(
            id=uuid4(),
            email="active@example.com",
            role="user",
            is_active=True,
            email_verified=True,
            email_otp_enabled=False,
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
            email_otp_enabled=user.email_otp_enabled,
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

    user = await _service().set_user_email_otp(
        db_session=_DBSessionStub(
            [SimpleNamespace(scalar_one_or_none=lambda: SimpleNamespace(id=uuid4()))]
        ),  # type: ignore[arg-type]
        user_id=uuid4(),
        enabled=True,
    )
    assert user.email_otp_enabled is True

    active_user_db = _DBSessionStub([SimpleNamespace(scalar_one_or_none=lambda: None)])
    with pytest.raises(AdminServiceError):
        await _service().revoke_user_sessions(
            db_session=active_user_db,  # type: ignore[arg-type]
            user_id=uuid4(),
        )
