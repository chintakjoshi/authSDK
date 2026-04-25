"""Additional unit tests for admin service error mapping and gates."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from app.core.sessions import SessionStateError
from app.core.signing_keys import SigningKeyRotationResult
from app.services.admin_service import AdminService, AdminServiceError
from app.services.erasure_service import ErasedUserResult, ErasureServiceError
from app.services.mfa_service import MfaServiceError
from app.services.user_service import UserServiceError
from app.services.webhook_service import DeletedWebhookEndpoint, WebhookServiceError


@dataclass
class _UserStub:
    id: object
    email: str
    role: str
    is_active: bool
    email_verified: bool
    mfa_enabled: bool
    created_at: datetime
    updated_at: datetime


class _DBSessionStub:
    def __init__(self) -> None:
        self.commit_count = 0
        self.rollback_count = 0

    async def commit(self) -> None:
        self.commit_count += 1

    async def rollback(self) -> None:
        self.rollback_count += 1

    async def execute(self, statement):  # type: ignore[no-untyped-def]
        del statement
        return self

    def scalar_one_or_none(self):  # type: ignore[no-untyped-def]
        return None

    def scalar_one(self):  # type: ignore[no-untyped-def]
        return 3


class _MfaServiceStub:
    def __init__(self) -> None:
        self.claims: dict[str, object] = {
            "sub": "admin-1",
            "role": "admin",
            "auth_time": int(datetime.now(UTC).timestamp()),
        }
        self.validate_error: MfaServiceError | None = None
        self.action_valid = False
        self.require_error: MfaServiceError | None = None
        self.enable_error: MfaServiceError | None = None
        self.disable_error: MfaServiceError | None = None

    async def validate_access_token(self, *, db_session, token):  # type: ignore[no-untyped-def]
        del db_session, token
        if self.validate_error is not None:
            raise self.validate_error
        return self.claims

    async def validate_action_token_for_user(
        self,
        *,
        db_session,
        token,
        expected_action,
        user_id,
    ):  # type: ignore[no-untyped-def]
        del db_session, token, expected_action, user_id
        return self.action_valid

    async def require_action_token_for_user(
        self,
        *,
        db_session,
        token,
        expected_action,
        user_id,
    ):  # type: ignore[no-untyped-def]
        del db_session, token, expected_action, user_id
        if self.require_error is not None:
            raise self.require_error

    async def set_user_mfa_state(self, *, db_session, user_id, enabled):  # type: ignore[no-untyped-def]
        del db_session, user_id
        if enabled:
            if self.enable_error is not None:
                raise self.enable_error
            return _UserStub(
                id=uuid4(),
                email="user@example.com",
                role="user",
                is_active=True,
                email_verified=True,
                mfa_enabled=True,
                created_at=datetime.now(UTC),
                updated_at=datetime.now(UTC),
            )
        if self.disable_error is not None:
            raise self.disable_error
        return _UserStub(
            id=uuid4(),
            email="user@example.com",
            role="user",
            is_active=True,
            email_verified=True,
            mfa_enabled=False,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )


class _UserServiceStub:
    def __init__(self) -> None:
        self.delete_error: UserServiceError | None = None

    async def delete_user(self, **kwargs):  # type: ignore[no-untyped-def]
        if self.delete_error is not None:
            raise self.delete_error
        return _UserStub(
            id=kwargs["user_id"],
            email="deleted@example.com",
            role="user",
            is_active=False,
            email_verified=True,
            mfa_enabled=False,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )


class _SessionServiceStub:
    def __init__(self) -> None:
        self.error: SessionStateError | None = None

    async def revoke_user_sessions(self, **kwargs):  # type: ignore[no-untyped-def]
        if self.error is not None:
            raise self.error
        return [uuid4()]


class _BruteForceServiceStub:
    async def get_lock_status(self, user_id: str) -> tuple[bool, int | None]:
        del user_id
        return False, None


class _APIKeyServiceStub:
    def __init__(self) -> None:
        self.revoked_user_ids: list[object] = []

    async def list_keys_page(self, **kwargs):  # type: ignore[no-untyped-def]
        return {"ok": True, **kwargs}

    async def revoke_user_keys(
        self,
        *,
        db_session,
        user_id,
        commit,
    ):  # type: ignore[no-untyped-def]
        del db_session
        self.revoked_user_ids.append((user_id, commit))
        return []


class _M2MServiceStub:
    async def list_clients_page(self, **kwargs):  # type: ignore[no-untyped-def]
        return {"ok": True, **kwargs}


class _WebhookServiceStub:
    def __init__(self) -> None:
        self.error: WebhookServiceError | None = None

    async def list_endpoints_page(self, **kwargs):  # type: ignore[no-untyped-def]
        return {"kind": "endpoints", **kwargs}

    async def get_endpoint(self, **kwargs):  # type: ignore[no-untyped-def]
        if self.error is not None:
            raise self.error
        return object()

    async def list_deliveries_page(self, **kwargs):  # type: ignore[no-untyped-def]
        return {"kind": "deliveries", **kwargs}

    async def delete_endpoint(self, **kwargs):  # type: ignore[no-untyped-def]
        if self.error is not None:
            raise self.error
        return DeletedWebhookEndpoint(id=kwargs["endpoint_id"], abandoned_delivery_ids=[])

    async def update_endpoint(self, **kwargs):  # type: ignore[no-untyped-def]
        if self.error is not None:
            raise self.error
        return {"updated": True}


class _AuditServiceStub:
    async def list_events_page(self, **kwargs):  # type: ignore[no-untyped-def]
        return {"kind": "audit", **kwargs}


class _SigningKeyServiceStub:
    async def rotate_signing_key(
        self,
        *,
        db_session,
        rotation_overlap_seconds,
    ):  # type: ignore[no-untyped-def]
        del db_session, rotation_overlap_seconds
        return SigningKeyRotationResult(new_kid="new-kid", retiring_kid="old-kid")


class _ErasureServiceStub:
    def __init__(self) -> None:
        self.error: ErasureServiceError | None = None

    async def erase_user(self, *, db_session, user_id):  # type: ignore[no-untyped-def]
        del db_session
        if self.error is not None:
            raise self.error
        return ErasedUserResult(
            user_id=user_id,
            anonymized_email=f"deleted_{user_id}@erased.invalid",
            deleted_identity_count=1,
            revoked_session_ids=[],
            revoked_api_key_ids=[],
        )


def _service(
    *,
    user_service: _UserServiceStub | None = None,
    session_service: _SessionServiceStub | None = None,
    mfa_service: _MfaServiceStub | None = None,
    api_key_service: _APIKeyServiceStub | None = None,
    webhook_service: _WebhookServiceStub | None = None,
    erasure_service: _ErasureServiceStub | None = None,
) -> AdminService:
    return AdminService(
        user_service=user_service or _UserServiceStub(),  # type: ignore[arg-type]
        session_service=session_service or _SessionServiceStub(),  # type: ignore[arg-type]
        mfa_service=mfa_service or _MfaServiceStub(),  # type: ignore[arg-type]
        brute_force_service=_BruteForceServiceStub(),  # type: ignore[arg-type]
        api_key_service=api_key_service or _APIKeyServiceStub(),  # type: ignore[arg-type]
        m2m_service=_M2MServiceStub(),  # type: ignore[arg-type]
        webhook_service=webhook_service or _WebhookServiceStub(),  # type: ignore[arg-type]
        audit_service=_AuditServiceStub(),  # type: ignore[arg-type]
        signing_key_service=_SigningKeyServiceStub(),  # type: ignore[arg-type]
        erasure_service=erasure_service or _ErasureServiceStub(),  # type: ignore[arg-type]
        enable_retention_purge=False,
        audit_log_retention_days=90,
        session_log_retention_days=30,
    )


@pytest.mark.asyncio
async def test_validate_admin_access_token_enforces_presence_role_and_error_mapping() -> None:
    """Admin access validation rejects missing tokens, non-admins, and OTP validation errors."""
    service = _service()
    with pytest.raises(AdminServiceError) as exc_info:
        await service.validate_admin_access_token(db_session=_DBSessionStub(), token="   ")  # type: ignore[arg-type]
    assert exc_info.value.code == "invalid_token"

    mfa_service = _MfaServiceStub()
    mfa_service.claims = {"sub": "user-1", "role": "user"}
    service = _service(mfa_service=mfa_service)
    with pytest.raises(AdminServiceError) as exc_info:
        await service.validate_admin_access_token(db_session=_DBSessionStub(), token="access")  # type: ignore[arg-type]
    assert exc_info.value.code == "insufficient_role"

    mfa_service.validate_error = MfaServiceError(
        "expired", "session_expired", 401, headers={"Retry-After": "1"}
    )
    with pytest.raises(AdminServiceError) as exc_info:
        await service.validate_admin_access_token(db_session=_DBSessionStub(), token="access")  # type: ignore[arg-type]
    assert exc_info.value.headers["Retry-After"] == "1"


@pytest.mark.asyncio
async def test_sensitive_action_gate_supports_dual_gate_contract() -> None:
    """Sensitive admin operations accept valid action tokens or require OTP/reauth fallbacks."""
    mfa_service = _MfaServiceStub()
    service = _service(mfa_service=mfa_service)

    mfa_service.action_valid = True
    await service.enforce_sensitive_action_gate(
        db_session=_DBSessionStub(),  # type: ignore[arg-type]
        claims={"sub": "admin-1", "mfa_enabled": True},
        action="role_change",
        action_token="action-token",
    )

    mfa_service.action_valid = False
    with pytest.raises(AdminServiceError) as exc_info:
        await service.enforce_sensitive_action_gate(
            db_session=_DBSessionStub(),  # type: ignore[arg-type]
            claims={"sub": "admin-1", "mfa_enabled": True},
            action="role_change",
            action_token=None,
        )
    assert exc_info.value.code == "otp_required"

    stale_claims = {
        "sub": "admin-1",
        "mfa_enabled": False,
        "auth_time": int((datetime.now(UTC) - timedelta(minutes=10)).timestamp()),
    }
    with pytest.raises(AdminServiceError) as exc_info:
        await service.enforce_sensitive_action_gate(
            db_session=_DBSessionStub(),  # type: ignore[arg-type]
            claims=stale_claims,
            action="role_change",
            action_token=None,
        )
    assert exc_info.value.code == "reauth_required"


@pytest.mark.asyncio
async def test_proxy_and_mutation_paths_map_errors() -> None:
    """Delete/session/OTP/webhook/erasure flows preserve stable admin error contracts."""
    mfa_service = _MfaServiceStub()
    mfa_service.require_error = MfaServiceError(
        "invalid", "action_token_invalid", 403, headers={"X-OTP-Required": "true"}
    )
    service = _service(mfa_service=mfa_service)
    with pytest.raises(AdminServiceError) as exc_info:
        await service.require_action_token(
            db_session=_DBSessionStub(),  # type: ignore[arg-type]
            claims={"sub": "admin-1"},
            action="admin_erase_user",
            action_token=None,
        )
    assert exc_info.value.headers["X-OTP-Required"] == "true"

    user_service = _UserServiceStub()
    user_service.delete_error = UserServiceError("boom", "invalid_user", 404)
    db_session = _DBSessionStub()
    service = _service(user_service=user_service)
    with pytest.raises(AdminServiceError):
        await service.delete_user(db_session=db_session, user_id=uuid4())  # type: ignore[arg-type]
    assert db_session.rollback_count == 1

    session_service = _SessionServiceStub()
    session_service.error = SessionStateError("expired", "session_expired", 401)
    service = _service(session_service=session_service)

    async def _active_user(**kwargs: object) -> _UserStub:
        return _UserStub(
            id=kwargs["user_id"],
            email="user@example.com",
            role="user",
            is_active=True,
            email_verified=True,
            mfa_enabled=False,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )

    service._get_active_user = _active_user  # type: ignore[assignment]
    with pytest.raises(AdminServiceError):
        await service.revoke_user_sessions(
            db_session=_DBSessionStub(),  # type: ignore[arg-type]
            user_id=uuid4(),
        )

    mfa_service = _MfaServiceStub()
    service = _service(mfa_service=mfa_service)

    async def _active_user(**kwargs: object) -> _UserStub:
        return _UserStub(
            id=kwargs["user_id"],
            email="user@example.com",
            role="user",
            is_active=True,
            email_verified=True,
            mfa_enabled=False,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )

    service._get_active_user = _active_user  # type: ignore[assignment]
    enabled = await service.set_user_mfa(
        db_session=_DBSessionStub(),  # type: ignore[arg-type]
        user_id=uuid4(),
        enabled=True,
    )
    assert enabled.mfa_enabled is True

    mfa_service.disable_error = MfaServiceError("missing", "invalid_token", 401)
    with pytest.raises(AdminServiceError) as exc_info:
        await service.set_user_mfa(
            db_session=_DBSessionStub(),  # type: ignore[arg-type]
            user_id=uuid4(),
            enabled=False,
        )
    assert exc_info.value.code == "invalid_user"

    webhook_service = _WebhookServiceStub()
    webhook_service.error = WebhookServiceError("missing", "invalid_credentials", 404)
    service = _service(webhook_service=webhook_service)
    with pytest.raises(AdminServiceError):
        await service.list_webhook_deliveries_page(
            db_session=_DBSessionStub(),  # type: ignore[arg-type]
            endpoint_id=uuid4(),
        )
    with pytest.raises(AdminServiceError):
        await service.delete_webhook(
            db_session=_DBSessionStub(),  # type: ignore[arg-type]
            endpoint_id=uuid4(),
        )

    erasure_service = _ErasureServiceStub()
    erasure_service.error = ErasureServiceError("gone", "already_erased", 409)
    service = _service(erasure_service=erasure_service)
    with pytest.raises(AdminServiceError) as exc_info:
        await service.erase_user(
            db_session=_DBSessionStub(),  # type: ignore[arg-type]
            user_id=uuid4(),
        )
    assert exc_info.value.code == "already_erased"


@pytest.mark.asyncio
async def test_delete_user_revokes_user_bound_api_keys_in_same_transaction() -> None:
    """Admin deletion revokes user-bound API keys before the transaction commits."""
    db_session = _DBSessionStub()
    api_key_service = _APIKeyServiceStub()
    deleted_user_id = uuid4()

    result = await _service(api_key_service=api_key_service).delete_user(
        db_session=db_session,  # type: ignore[arg-type]
        user_id=deleted_user_id,
    )

    assert result.user_id == deleted_user_id
    assert api_key_service.revoked_user_ids == [(deleted_user_id, False)]
    assert db_session.commit_count == 1


@pytest.mark.asyncio
async def test_rotate_signing_key_commits_and_retention_uses_config() -> None:
    """Signing-key rotation commits and retention purge returns configured values."""
    db_session = _DBSessionStub()
    service = _service()

    result = await service.rotate_signing_key(
        db_session=db_session,  # type: ignore[arg-type]
        rotation_overlap_seconds=60,
    )
    retention = await service.run_retention_purge(db_session=db_session)  # type: ignore[arg-type]

    assert result.new_kid == "new-kid"
    assert db_session.commit_count == 1
    assert retention.enabled is False
