"""Tests for MfaService access-token, action-token, and admin-toggle helpers.

These methods are the surface previously exposed by ``OTPService`` that
non-OTP flows (admin, lifecycle, self-service, erasure) depend on. They land
on ``MfaService`` in Phase 5a so the legacy ``OTPService`` becomes an
unreferenced dead module before Phase 5b deletes it.
"""

from __future__ import annotations

from uuid import uuid4

import pytest

from app.models.user import User
from app.services.mfa_service import (
    AccessTokenValidationResult,
    MfaService,
    MfaServiceError,
)
from tests.unit.support.mfa import MfaServiceTestEnvironment, build_test_environment


@pytest.fixture()
def env() -> MfaServiceTestEnvironment:
    return build_test_environment()


@pytest.fixture()
def mfa_service(env: MfaServiceTestEnvironment) -> MfaService:
    return env.service


def _make_active_user(
    env: MfaServiceTestEnvironment,
    *,
    role: str = "user",
    mfa_enabled: bool = False,
    phone_verified: bool = False,
) -> User:
    user = User(
        id=uuid4(),
        email="user@example.com",
        password_hash="hash",
        is_active=True,
        email_verified=True,
        role=role,
        phone_verified=phone_verified,
        mfa_enabled=mfa_enabled,
    )
    env.db.users[str(user.id)] = user
    return user


class TestValidateAccessToken:
    """``validate_access_token`` mirrors the legacy OTP-service surface for routers."""

    @pytest.mark.asyncio
    async def test_returns_claims_for_valid_access_token(
        self,
        mfa_service: MfaService,
        env: MfaServiceTestEnvironment,
    ) -> None:
        user = _make_active_user(env)
        token = await env.mint_access_token(user_id=str(user.id))
        decoded = env.decode_access_token(token)
        env.session_service.bound_sessions[decoded["jti"]] = uuid4()

        claims = await mfa_service.validate_access_token(
            db_session=env.db,
            token=token,
        )

        assert claims["sub"] == str(user.id)
        assert claims["type"] == "access"

    @pytest.mark.asyncio
    async def test_rejects_invalid_token(
        self,
        mfa_service: MfaService,
        env: MfaServiceTestEnvironment,
    ) -> None:
        with pytest.raises(MfaServiceError) as info:
            await mfa_service.validate_access_token(
                db_session=env.db,
                token="garbage",
            )
        assert info.value.code == "invalid_token"
        assert info.value.status_code == 401

    @pytest.mark.asyncio
    async def test_rejects_revoked_access_token(
        self,
        mfa_service: MfaService,
        env: MfaServiceTestEnvironment,
    ) -> None:
        user = _make_active_user(env)
        token = await env.mint_access_token(user_id=str(user.id))
        decoded = env.decode_access_token(token)
        env.session_service.bound_sessions[decoded["jti"]] = uuid4()
        # Blocklist the JTI to simulate revoke.
        env.redis.scalars[f"blocklist:jti:{decoded['jti']}"] = "1"

        with pytest.raises(MfaServiceError) as info:
            await mfa_service.validate_access_token(
                db_session=env.db,
                token=token,
            )
        assert info.value.code == "invalid_token"

    @pytest.mark.asyncio
    async def test_rejects_wrong_token_type(
        self,
        mfa_service: MfaService,
        env: MfaServiceTestEnvironment,
    ) -> None:
        user = _make_active_user(env)
        # Action tokens must be rejected by the access-token validator.
        action_token = await env.mint_action_token(
            user_id=str(user.id),
            action="role_change",
        )

        with pytest.raises(MfaServiceError) as info:
            await mfa_service.validate_access_token(
                db_session=env.db,
                token=action_token,
            )
        assert info.value.code == "invalid_token"


class TestValidateAccessTokenWithSession:
    """``validate_access_token_with_session`` returns claims plus the bound session."""

    @pytest.mark.asyncio
    async def test_returns_session_id_for_active_session(
        self,
        mfa_service: MfaService,
        env: MfaServiceTestEnvironment,
    ) -> None:
        user = _make_active_user(env)
        token = await env.mint_access_token(user_id=str(user.id))
        decoded = env.decode_access_token(token)
        session_id = uuid4()
        env.session_service.bound_sessions[decoded["jti"]] = session_id

        result = await mfa_service.validate_access_token_with_session(
            db_session=env.db,
            token=token,
        )

        assert isinstance(result, AccessTokenValidationResult)
        assert result.claims["sub"] == str(user.id)
        assert result.session_id == session_id

    @pytest.mark.asyncio
    async def test_raises_when_session_no_longer_active(
        self,
        mfa_service: MfaService,
        env: MfaServiceTestEnvironment,
    ) -> None:
        user = _make_active_user(env)
        token = await env.mint_access_token(user_id=str(user.id))
        # Do not bind the JTI to a session; SessionService raises session_expired.

        with pytest.raises(MfaServiceError) as info:
            await mfa_service.validate_access_token_with_session(
                db_session=env.db,
                token=token,
            )
        assert info.value.code == "session_expired"


class TestRequireActionTokenForUser:
    """``require_action_token_for_user`` raises on missing/wrong tokens."""

    @pytest.mark.asyncio
    async def test_accepts_valid_action_token(
        self,
        mfa_service: MfaService,
        env: MfaServiceTestEnvironment,
    ) -> None:
        user = _make_active_user(env)
        token = await env.mint_action_token(
            user_id=str(user.id),
            action="erase_account",
        )

        # Should not raise.
        await mfa_service.require_action_token_for_user(
            db_session=env.db,
            token=token,
            expected_action="erase_account",
            user_id=str(user.id),
        )

    @pytest.mark.asyncio
    async def test_raises_for_missing_token(
        self,
        mfa_service: MfaService,
        env: MfaServiceTestEnvironment,
    ) -> None:
        user = _make_active_user(env)

        with pytest.raises(MfaServiceError) as info:
            await mfa_service.require_action_token_for_user(
                db_session=env.db,
                token=None,
                expected_action="erase_account",
                user_id=str(user.id),
            )
        assert info.value.code == "action_token_invalid"
        assert info.value.status_code == 403

    @pytest.mark.asyncio
    async def test_raises_for_action_mismatch(
        self,
        mfa_service: MfaService,
        env: MfaServiceTestEnvironment,
    ) -> None:
        user = _make_active_user(env)
        wrong_token = await env.mint_action_token(
            user_id=str(user.id),
            action="role_change",
        )

        with pytest.raises(MfaServiceError):
            await mfa_service.require_action_token_for_user(
                db_session=env.db,
                token=wrong_token,
                expected_action="erase_account",
                user_id=str(user.id),
            )


class TestClearUserMfaState:
    """``clear_user_mfa_state`` removes per-user challenge rows and resend counters."""

    @pytest.mark.asyncio
    async def test_clears_all_challenge_purposes(
        self,
        mfa_service: MfaService,
        env: MfaServiceTestEnvironment,
    ) -> None:
        user_id = str(uuid4())
        # Seed challenges across all three purposes.
        for purpose in ("login", "action", "phone_verify"):
            await env.challenge_store.store(
                user_id=user_id,
                purpose=purpose,  # type: ignore[arg-type]
                method="sms",
                code_hash="h",
                jti=f"j-{purpose}",
                ttl_seconds=600,
            )
        # Seed a resend counter.
        env.redis.scalars[f"mfa:resend:login:{user_id}"] = "2"

        await mfa_service.clear_user_mfa_state(user_id=user_id)

        for purpose in ("login", "action", "phone_verify"):
            assert (
                await env.challenge_store.load(
                    user_id=user_id,
                    purpose=purpose,  # type: ignore[arg-type]
                )
                is None
            )
        assert f"mfa:resend:login:{user_id}" not in env.redis.scalars


class TestSetUserMfaState:
    """``set_user_mfa_state`` is the admin-toggle path bypassing action tokens."""

    @pytest.mark.asyncio
    async def test_enables_mfa_when_phone_verified(
        self,
        mfa_service: MfaService,
        env: MfaServiceTestEnvironment,
    ) -> None:
        user = _make_active_user(env, phone_verified=True)
        user.phone_ciphertext = env.phone_cipher.encrypt("+14155552671")
        user.phone_last4 = "2671"
        user.phone_lookup_hash = env.phone_hasher.lookup_hash("+14155552671")

        result = await mfa_service.set_user_mfa_state(
            db_session=env.db,
            user_id=str(user.id),
            enabled=True,
        )

        assert result.mfa_enabled is True
        assert result.mfa_primary_method == "sms"

    @pytest.mark.asyncio
    async def test_enable_rejects_without_verified_phone(
        self,
        mfa_service: MfaService,
        env: MfaServiceTestEnvironment,
    ) -> None:
        user = _make_active_user(env)

        with pytest.raises(MfaServiceError) as info:
            await mfa_service.set_user_mfa_state(
                db_session=env.db,
                user_id=str(user.id),
                enabled=True,
            )
        assert info.value.code == "phone_not_verified"

    @pytest.mark.asyncio
    async def test_disables_mfa_clears_recovery_codes(
        self,
        mfa_service: MfaService,
        env: MfaServiceTestEnvironment,
    ) -> None:
        user = _make_active_user(env, mfa_enabled=True)
        user.mfa_primary_method = "sms"
        await env._persist_recovery_code(  # type: ignore[attr-defined]
            user_id=user.id,
            code_hash="prior-hash-1",
        )

        result = await mfa_service.set_user_mfa_state(
            db_session=env.db,
            user_id=str(user.id),
            enabled=False,
        )

        assert result.mfa_enabled is False
        assert result.mfa_primary_method is None
        for row in env.db.recovery_codes.values():
            if row.user_id == user.id:
                assert row.used_at is not None

    @pytest.mark.asyncio
    async def test_unknown_user_returns_invalid_token(
        self,
        mfa_service: MfaService,
    ) -> None:
        env_local = build_test_environment()

        with pytest.raises(MfaServiceError) as info:
            await env_local.service.set_user_mfa_state(
                db_session=env_local.db,
                user_id=str(uuid4()),
                enabled=True,
            )
        assert info.value.code == "invalid_token"
