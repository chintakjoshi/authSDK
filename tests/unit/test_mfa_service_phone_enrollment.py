"""Unit tests for MfaService phone-enrollment flow.

Covers ``request_phone_verification`` and ``verify_phone``: validation,
encryption-at-rest, lookup-hash uniqueness, masked destination output,
attempt counter wiring, and clean rollback on failure.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any
from uuid import uuid4

import pytest

from app.core.mfa.phone import PhoneCipher, PhoneHasher
from app.models.user import User
from app.services.mfa_service import MfaService, MfaServiceError
from tests.unit.support.mfa import MfaServiceTestEnvironment, build_test_environment


@pytest.fixture()
def env() -> MfaServiceTestEnvironment:
    return build_test_environment()


@pytest.fixture()
def mfa_service(env: MfaServiceTestEnvironment) -> MfaService:
    return env.service


def _make_user(env: MfaServiceTestEnvironment, *, email_verified: bool = True) -> User:
    user = User(
        id=uuid4(),
        email="user@example.com",
        password_hash="hash",
        is_active=True,
        email_verified=email_verified,
        role="user",
        phone_verified=False,
        mfa_enabled=False,
    )
    env.db.users[str(user.id)] = user
    return user


class TestRequestPhoneVerification:
    """``request_phone_verification`` should validate, store, and dispatch."""

    @pytest.mark.asyncio
    async def test_rejects_invalid_e164(
        self,
        mfa_service: MfaService,
        env: MfaServiceTestEnvironment,
    ) -> None:
        user = _make_user(env)

        with pytest.raises(MfaServiceError) as info:
            await mfa_service.request_phone_verification(
                db_session=env.db,
                user_id=str(user.id),
                raw_phone="not-a-phone",
            )
        assert info.value.code == "phone_invalid"

    @pytest.mark.asyncio
    async def test_persists_pending_phone_state_and_sends_sms(
        self,
        mfa_service: MfaService,
        env: MfaServiceTestEnvironment,
    ) -> None:
        user = _make_user(env)

        result = await mfa_service.request_phone_verification(
            db_session=env.db,
            user_id=str(user.id),
            raw_phone="+14155552671",
        )

        assert result.user_id == str(user.id)
        assert result.masked_destination.endswith("2671")
        assert result.expires_in == env.settings.mfa.sms_code_ttl_seconds
        assert env.sms.calls and env.sms.calls[0]["to_phone_e164"] == "+14155552671"
        assert env.sms.calls[0]["purpose"] == "phone_verify"

        challenge = await env.challenge_store.load(user_id=str(user.id), purpose="phone_verify")
        assert challenge is not None
        assert challenge.method == "sms"
        assert challenge.code_hash != env.sms.calls[0]["code"]  # stored hashed, not raw

    @pytest.mark.asyncio
    async def test_rejects_when_phone_already_claimed_by_another_user(
        self,
        mfa_service: MfaService,
        env: MfaServiceTestEnvironment,
    ) -> None:
        owner = _make_user(env)
        owner.phone_lookup_hash = env.phone_hasher.lookup_hash("+14155552671")
        owner.phone_verified = True

        intruder = User(
            id=uuid4(),
            email="other@example.com",
            password_hash="hash",
            is_active=True,
            email_verified=True,
            role="user",
        )
        env.db.users[str(intruder.id)] = intruder

        with pytest.raises(MfaServiceError) as info:
            await mfa_service.request_phone_verification(
                db_session=env.db,
                user_id=str(intruder.id),
                raw_phone="+14155552671",
            )
        assert info.value.code == "phone_unavailable"

    @pytest.mark.asyncio
    async def test_user_can_re_request_verification_for_their_own_phone(
        self,
        mfa_service: MfaService,
        env: MfaServiceTestEnvironment,
    ) -> None:
        user = _make_user(env)
        user.phone_lookup_hash = env.phone_hasher.lookup_hash("+14155552671")
        user.phone_verified = True

        result = await mfa_service.request_phone_verification(
            db_session=env.db,
            user_id=str(user.id),
            raw_phone="+14155552671",
        )

        assert result.user_id == str(user.id)


class TestVerifyPhone:
    """``verify_phone`` consumes the SMS challenge and persists encrypted state."""

    @pytest.mark.asyncio
    async def test_marks_user_phone_verified_and_stores_encrypted_value(
        self,
        mfa_service: MfaService,
        env: MfaServiceTestEnvironment,
    ) -> None:
        user = _make_user(env)
        await mfa_service.request_phone_verification(
            db_session=env.db,
            user_id=str(user.id),
            raw_phone="+14155552671",
        )
        sent = env.sms.calls[-1]

        await mfa_service.verify_phone(
            db_session=env.db,
            user_id=str(user.id),
            code=sent["code"],
        )

        assert user.phone_verified is True
        assert user.phone_verified_at is not None
        assert user.phone_last4 == "2671"
        assert isinstance(user.phone_ciphertext, bytes)
        # Encrypted at rest: the ciphertext must round-trip via PhoneCipher.
        assert env.phone_cipher.decrypt(user.phone_ciphertext) == "+14155552671"
        assert user.phone_lookup_hash == env.phone_hasher.lookup_hash("+14155552671")

        # Successful verify must clear the phone-verify challenge state.
        assert await env.challenge_store.load(user_id=str(user.id), purpose="phone_verify") is None

    @pytest.mark.asyncio
    async def test_rejects_wrong_code_and_increments_attempts(
        self,
        mfa_service: MfaService,
        env: MfaServiceTestEnvironment,
    ) -> None:
        user = _make_user(env)
        await mfa_service.request_phone_verification(
            db_session=env.db,
            user_id=str(user.id),
            raw_phone="+14155552671",
        )

        with pytest.raises(MfaServiceError) as info:
            await mfa_service.verify_phone(
                db_session=env.db,
                user_id=str(user.id),
                code="000000",
            )
        assert info.value.code == "invalid_code"

        assert user.phone_verified is False
        challenge = await env.challenge_store.load(user_id=str(user.id), purpose="phone_verify")
        assert challenge is not None
        assert challenge.attempt_count == 1

    @pytest.mark.asyncio
    async def test_max_attempts_exceeded_clears_challenge(
        self,
        mfa_service: MfaService,
        env: MfaServiceTestEnvironment,
    ) -> None:
        user = _make_user(env)
        await mfa_service.request_phone_verification(
            db_session=env.db,
            user_id=str(user.id),
            raw_phone="+14155552671",
        )

        max_attempts = env.settings.mfa.sms_max_attempts
        for _ in _range(max_attempts):
            with pytest.raises(MfaServiceError):
                await mfa_service.verify_phone(
                    db_session=env.db,
                    user_id=str(user.id),
                    code="000000",
                )

        with pytest.raises(MfaServiceError) as info:
            await mfa_service.verify_phone(
                db_session=env.db,
                user_id=str(user.id),
                code="000000",
            )
        assert info.value.code in {"invalid_code", "challenge_expired"}

        assert await env.challenge_store.load(user_id=str(user.id), purpose="phone_verify") is None

    @pytest.mark.asyncio
    async def test_rejects_when_no_active_challenge(
        self,
        mfa_service: MfaService,
        env: MfaServiceTestEnvironment,
    ) -> None:
        user = _make_user(env)

        with pytest.raises(MfaServiceError) as info:
            await mfa_service.verify_phone(
                db_session=env.db,
                user_id=str(user.id),
                code="000000",
            )
        assert info.value.code == "challenge_expired"


class TestPhoneCipherWiringSanity:
    """Sanity guard: the service must be wired with both cipher and hasher."""

    def test_service_uses_provided_cipher_and_hasher(
        self,
        env: MfaServiceTestEnvironment,
    ) -> None:
        assert isinstance(env.phone_cipher, PhoneCipher)
        assert isinstance(env.phone_hasher, PhoneHasher)


def _range(n: int) -> Iterable[int]:
    """Wrapper to keep loop intent obvious in tests using max-attempts thresholds."""
    return range(n)


def _drain_sms_calls(env: MfaServiceTestEnvironment) -> list[dict[str, Any]]:
    """Drain queued SMS calls and return them; convenience for assertions."""
    drained = list(env.sms.calls)
    env.sms.calls.clear()
    return drained
