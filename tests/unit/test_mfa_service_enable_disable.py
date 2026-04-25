"""Unit tests for MfaService enable / disable / regenerate-recovery flows."""

from __future__ import annotations

from uuid import uuid4

import pytest

from app.core.mfa.codes import normalize_recovery_code
from app.models.user import User
from app.services.mfa_service import MfaService, MfaServiceError
from tests.unit.support.mfa import MfaServiceTestEnvironment, build_test_environment


@pytest.fixture()
def env() -> MfaServiceTestEnvironment:
    return build_test_environment()


@pytest.fixture()
def mfa_service(env: MfaServiceTestEnvironment) -> MfaService:
    return env.service


def _make_user_with_verified_phone(env: MfaServiceTestEnvironment) -> User:
    user = User(
        id=uuid4(),
        email="user@example.com",
        password_hash="hash",
        is_active=True,
        email_verified=True,
        role="user",
        phone_ciphertext=env.phone_cipher.encrypt("+14155552671"),
        phone_last4="2671",
        phone_lookup_hash=env.phone_hasher.lookup_hash("+14155552671"),
        phone_verified=True,
    )
    env.db.users[str(user.id)] = user
    return user


async def _mint_action_token(env: MfaServiceTestEnvironment, user: User, action: str) -> str:
    return await env.mint_action_token(user_id=str(user.id), action=action)


class TestEnableMfa:
    """``enable_mfa`` requires a verified phone and returns plaintext recovery codes once."""

    @pytest.mark.asyncio
    async def test_rejects_when_phone_not_verified(
        self,
        mfa_service: MfaService,
        env: MfaServiceTestEnvironment,
    ) -> None:
        user = _make_user_with_verified_phone(env)
        user.phone_verified = False
        token = await _mint_action_token(env, user, "enable_mfa")

        with pytest.raises(MfaServiceError) as info:
            await mfa_service.enable_mfa(
                db_session=env.db,
                user_id=str(user.id),
                action_token=token,
            )
        assert info.value.code == "phone_not_verified"

    @pytest.mark.asyncio
    async def test_rejects_when_action_token_missing(
        self,
        mfa_service: MfaService,
        env: MfaServiceTestEnvironment,
    ) -> None:
        user = _make_user_with_verified_phone(env)

        with pytest.raises(MfaServiceError) as info:
            await mfa_service.enable_mfa(
                db_session=env.db,
                user_id=str(user.id),
                action_token=None,
            )
        assert info.value.code == "action_token_invalid"

    @pytest.mark.asyncio
    async def test_rejects_when_action_token_for_different_action(
        self,
        mfa_service: MfaService,
        env: MfaServiceTestEnvironment,
    ) -> None:
        user = _make_user_with_verified_phone(env)
        wrong_token = await _mint_action_token(env, user, "disable_mfa")

        with pytest.raises(MfaServiceError) as info:
            await mfa_service.enable_mfa(
                db_session=env.db,
                user_id=str(user.id),
                action_token=wrong_token,
            )
        assert info.value.code == "action_token_invalid"

    @pytest.mark.asyncio
    async def test_enables_mfa_and_returns_one_time_recovery_codes(
        self,
        mfa_service: MfaService,
        env: MfaServiceTestEnvironment,
    ) -> None:
        user = _make_user_with_verified_phone(env)
        token = await _mint_action_token(env, user, "enable_mfa")

        result = await mfa_service.enable_mfa(
            db_session=env.db,
            user_id=str(user.id),
            action_token=token,
        )

        assert user.mfa_enabled is True
        assert user.mfa_primary_method == "sms"

        assert len(result.recovery_codes) == env.settings.mfa.recovery_code_count
        for code in result.recovery_codes:
            assert normalize_recovery_code(code) == code

        # Codes are persisted only as hashes; plaintext appears in the result and nowhere else.
        stored_hashes = {row.code_hash for row in env.db.recovery_codes.values()}
        assert len(stored_hashes) == len(result.recovery_codes)
        for plaintext in result.recovery_codes:
            assert plaintext not in stored_hashes

    @pytest.mark.asyncio
    async def test_rejects_when_already_enabled(
        self,
        mfa_service: MfaService,
        env: MfaServiceTestEnvironment,
    ) -> None:
        user = _make_user_with_verified_phone(env)
        user.mfa_enabled = True
        user.mfa_primary_method = "sms"
        token = await _mint_action_token(env, user, "enable_mfa")

        with pytest.raises(MfaServiceError) as info:
            await mfa_service.enable_mfa(
                db_session=env.db,
                user_id=str(user.id),
                action_token=token,
            )
        assert info.value.code == "mfa_already_enabled"


class TestDisableMfa:
    """``disable_mfa`` requires a step-up action token and clears MFA state."""

    @pytest.mark.asyncio
    async def test_rejects_when_action_token_missing(
        self,
        mfa_service: MfaService,
        env: MfaServiceTestEnvironment,
    ) -> None:
        user = _make_user_with_verified_phone(env)
        user.mfa_enabled = True
        user.mfa_primary_method = "sms"

        with pytest.raises(MfaServiceError) as info:
            await mfa_service.disable_mfa(
                db_session=env.db,
                user_id=str(user.id),
                action_token=None,
            )
        assert info.value.code == "action_token_invalid"

    @pytest.mark.asyncio
    async def test_disables_mfa_and_invalidates_recovery_codes_and_challenges(
        self,
        mfa_service: MfaService,
        env: MfaServiceTestEnvironment,
    ) -> None:
        user = _make_user_with_verified_phone(env)
        user.mfa_enabled = True
        user.mfa_primary_method = "sms"
        token = await _mint_action_token(env, user, "disable_mfa")

        # Seed a stored recovery-code row + an active challenge.
        await mfa_service.request_phone_verification(
            db_session=env.db,
            user_id=str(user.id),
            raw_phone="+14155552671",
        )
        await env._persist_recovery_code(user_id=user.id, code_hash="prior-hash-1")  # type: ignore[attr-defined]

        await mfa_service.disable_mfa(
            db_session=env.db,
            user_id=str(user.id),
            action_token=token,
        )

        assert user.mfa_enabled is False
        assert user.mfa_primary_method is None

        # All recovery codes for this user must be marked used.
        for row in env.db.recovery_codes.values():
            if row.user_id == user.id:
                assert row.used_at is not None

        # Active challenges should be cleared.
        assert await env.challenge_store.load(user_id=str(user.id), purpose="phone_verify") is None

    @pytest.mark.asyncio
    async def test_idempotent_when_already_disabled(
        self,
        mfa_service: MfaService,
        env: MfaServiceTestEnvironment,
    ) -> None:
        user = _make_user_with_verified_phone(env)
        token = await _mint_action_token(env, user, "disable_mfa")

        await mfa_service.disable_mfa(
            db_session=env.db,
            user_id=str(user.id),
            action_token=token,
        )

        assert user.mfa_enabled is False


class TestRegenerateRecoveryCodes:
    """Regeneration requires step-up, invalidates prior unused codes."""

    @pytest.mark.asyncio
    async def test_rejects_when_action_token_missing(
        self,
        mfa_service: MfaService,
        env: MfaServiceTestEnvironment,
    ) -> None:
        user = _make_user_with_verified_phone(env)
        user.mfa_enabled = True
        user.mfa_primary_method = "sms"

        with pytest.raises(MfaServiceError):
            await mfa_service.regenerate_recovery_codes(
                db_session=env.db,
                user_id=str(user.id),
                action_token=None,
            )

    @pytest.mark.asyncio
    async def test_invalidates_previous_unused_codes(
        self,
        mfa_service: MfaService,
        env: MfaServiceTestEnvironment,
    ) -> None:
        user = _make_user_with_verified_phone(env)
        user.mfa_enabled = True
        user.mfa_primary_method = "sms"
        await env._persist_recovery_code(user_id=user.id, code_hash="prior-hash-1")  # type: ignore[attr-defined]
        await env._persist_recovery_code(user_id=user.id, code_hash="prior-hash-2")  # type: ignore[attr-defined]
        token = await _mint_action_token(env, user, "regenerate_recovery_codes")

        new_codes = await mfa_service.regenerate_recovery_codes(
            db_session=env.db,
            user_id=str(user.id),
            action_token=token,
        )

        assert len(new_codes) == env.settings.mfa.recovery_code_count

        # Every prior code must now be marked used; new codes must be unused.
        prior_rows = [
            row for row in env.db.recovery_codes.values() if row.code_hash.startswith("prior-")
        ]
        assert prior_rows
        for row in prior_rows:
            assert row.used_at is not None

        unused_rows = [
            row
            for row in env.db.recovery_codes.values()
            if row.user_id == user.id and row.used_at is None
        ]
        assert len(unused_rows) == env.settings.mfa.recovery_code_count
