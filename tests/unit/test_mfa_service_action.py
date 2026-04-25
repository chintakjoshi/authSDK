"""Unit tests for MfaService action-OTP flow."""

from __future__ import annotations

from uuid import uuid4

import pytest

from app.models.user import User
from app.services.mfa_service import MfaService, MfaServiceError
from tests.unit.support.mfa import MfaServiceTestEnvironment, build_test_environment


@pytest.fixture()
def env() -> MfaServiceTestEnvironment:
    return build_test_environment()


@pytest.fixture()
def mfa_service(env: MfaServiceTestEnvironment) -> MfaService:
    return env.service


def _make_enrolled_user(env: MfaServiceTestEnvironment) -> User:
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
        mfa_enabled=True,
        mfa_primary_method="sms",
    )
    env.db.users[str(user.id)] = user
    return user


class TestRequestActionCode:
    """Action OTP requires a verified phone and writes a fresh challenge row."""

    @pytest.mark.asyncio
    async def test_request_dispatches_action_sms(
        self,
        mfa_service: MfaService,
        env: MfaServiceTestEnvironment,
    ) -> None:
        user = _make_enrolled_user(env)

        result = await mfa_service.request_action_code(
            db_session=env.db,
            user_id=str(user.id),
            action="role_change",
        )

        assert result.user_id == str(user.id)
        assert result.action == "role_change"
        assert result.expires_in == env.settings.mfa.sms_code_ttl_seconds
        assert env.sms.calls[-1]["purpose"] == "action"
        challenge = await env.challenge_store.load(user_id=str(user.id), purpose="action")
        assert challenge is not None

    @pytest.mark.asyncio
    async def test_request_rejects_when_phone_unverified(
        self,
        mfa_service: MfaService,
        env: MfaServiceTestEnvironment,
    ) -> None:
        user = User(
            id=uuid4(),
            email="user@example.com",
            password_hash="hash",
            is_active=True,
            email_verified=True,
            role="user",
            phone_verified=False,
        )
        env.db.users[str(user.id)] = user

        with pytest.raises(MfaServiceError) as info:
            await mfa_service.request_action_code(
                db_session=env.db,
                user_id=str(user.id),
                action="role_change",
            )
        assert info.value.code == "phone_not_verified"


class TestVerifyActionCode:
    """Action verify mints a single-use action token bound to the user/action."""

    @pytest.mark.asyncio
    async def test_correct_code_mints_action_token_and_clears_challenge(
        self,
        mfa_service: MfaService,
        env: MfaServiceTestEnvironment,
    ) -> None:
        user = _make_enrolled_user(env)
        await mfa_service.request_action_code(
            db_session=env.db,
            user_id=str(user.id),
            action="role_change",
        )
        sent = env.sms.calls[-1]

        result = await mfa_service.verify_action_code(
            db_session=env.db,
            user_id=str(user.id),
            code=sent["code"],
            action="role_change",
            audience=None,
        )

        assert result.action == "role_change"
        assert result.action_token

        decoded = env.decode_action_token(result.action_token)
        assert decoded["sub"] == str(user.id)
        assert decoded["action"] == "role_change"
        assert decoded["type"] == "action_token"

        assert await env.challenge_store.load(user_id=str(user.id), purpose="action") is None

    @pytest.mark.asyncio
    async def test_action_mismatch_is_rejected(
        self,
        mfa_service: MfaService,
        env: MfaServiceTestEnvironment,
    ) -> None:
        user = _make_enrolled_user(env)
        await mfa_service.request_action_code(
            db_session=env.db,
            user_id=str(user.id),
            action="role_change",
        )
        sent = env.sms.calls[-1]

        with pytest.raises(MfaServiceError) as info:
            await mfa_service.verify_action_code(
                db_session=env.db,
                user_id=str(user.id),
                code=sent["code"],
                action="delete_user",
                audience=None,
            )
        assert info.value.code in {"otp_action_mismatch", "invalid_code"}

    @pytest.mark.asyncio
    async def test_wrong_code_is_rejected(
        self,
        mfa_service: MfaService,
        env: MfaServiceTestEnvironment,
    ) -> None:
        user = _make_enrolled_user(env)
        await mfa_service.request_action_code(
            db_session=env.db,
            user_id=str(user.id),
            action="role_change",
        )

        with pytest.raises(MfaServiceError) as info:
            await mfa_service.verify_action_code(
                db_session=env.db,
                user_id=str(user.id),
                code="000000",
                action="role_change",
                audience=None,
            )
        assert info.value.code == "invalid_code"

    @pytest.mark.asyncio
    async def test_action_token_validation_helper_round_trip(
        self,
        mfa_service: MfaService,
        env: MfaServiceTestEnvironment,
    ) -> None:
        user = _make_enrolled_user(env)
        await mfa_service.request_action_code(
            db_session=env.db,
            user_id=str(user.id),
            action="role_change",
        )
        sent = env.sms.calls[-1]

        verified = await mfa_service.verify_action_code(
            db_session=env.db,
            user_id=str(user.id),
            code=sent["code"],
            action="role_change",
            audience=None,
        )

        ok = await mfa_service.validate_action_token_for_user(
            db_session=env.db,
            token=verified.action_token,
            expected_action="role_change",
            user_id=str(user.id),
        )
        assert ok is True

        wrong = await mfa_service.validate_action_token_for_user(
            db_session=env.db,
            token=verified.action_token,
            expected_action="delete_user",
            user_id=str(user.id),
        )
        assert wrong is False
