"""Unit tests for MfaService login challenge / verify / resend flows."""

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


class TestStartLoginChallenge:
    """Login challenges issue a JWT bound to Redis state and dispatch SMS."""

    @pytest.mark.asyncio
    async def test_emits_challenge_token_with_jti_bound_to_redis(
        self,
        mfa_service: MfaService,
        env: MfaServiceTestEnvironment,
    ) -> None:
        user = _make_enrolled_user(env)

        result = await mfa_service.start_login_challenge(
            db_session=env.db,
            user=user,
            requested_audience=None,
        )

        assert result.user_id == str(user.id)
        assert result.method == "sms"
        assert result.masked_destination.endswith("2671")
        assert result.expires_in == env.settings.mfa.challenge_ttl_seconds

        decoded = env.decode_challenge_token(result.challenge_token)
        challenge = await env.challenge_store.load(user_id=str(user.id), purpose="login")
        assert challenge is not None
        assert challenge.jti == decoded["jti"]
        # SMS dispatched, code stored only as a hash.
        assert env.sms.calls
        assert env.sms.calls[-1]["purpose"] == "login"
        assert env.sms.calls[-1]["to_phone_e164"] == "+14155552671"
        assert challenge.code_hash != env.sms.calls[-1]["code"]

    @pytest.mark.asyncio
    async def test_preserves_requested_audience_in_challenge_state(
        self,
        mfa_service: MfaService,
        env: MfaServiceTestEnvironment,
    ) -> None:
        user = _make_enrolled_user(env)

        await mfa_service.start_login_challenge(
            db_session=env.db,
            user=user,
            requested_audience="reporting-service",
        )

        challenge = await env.challenge_store.load(user_id=str(user.id), purpose="login")
        assert challenge is not None
        # Either str preserved as a list-coerced or as a plain string is acceptable
        # — the test only requires the requested audience to be retrievable.
        assert challenge.audience is not None
        if isinstance(challenge.audience, list):
            assert "reporting-service" in challenge.audience
        else:
            assert challenge.audience == "reporting-service"

    @pytest.mark.asyncio
    async def test_rejects_when_phone_not_verified(
        self,
        mfa_service: MfaService,
        env: MfaServiceTestEnvironment,
    ) -> None:
        user = _make_enrolled_user(env)
        user.phone_verified = False

        with pytest.raises(MfaServiceError) as info:
            await mfa_service.start_login_challenge(
                db_session=env.db,
                user=user,
                requested_audience=None,
            )
        assert info.value.code == "phone_not_verified"


class TestVerifyLoginWithSmsCode:
    """SMS-code login verification issues tokens and creates a session."""

    @pytest.mark.asyncio
    async def test_correct_code_issues_tokens_and_clears_challenge(
        self,
        mfa_service: MfaService,
        env: MfaServiceTestEnvironment,
    ) -> None:
        user = _make_enrolled_user(env)
        challenge = await mfa_service.start_login_challenge(
            db_session=env.db, user=user, requested_audience=None
        )
        sent = env.sms.calls[-1]

        result = await mfa_service.verify_login(
            db_session=env.db,
            challenge_token=challenge.challenge_token,
            code=sent["code"],
            recovery_code=None,
            client_ip="203.0.113.10",
            user_agent="pytest",
        )

        assert result.user_id == str(user.id)
        assert result.token_pair.access_token
        assert result.token_pair.refresh_token
        assert result.method_used == "sms"
        assert result.session_id is not None
        # Challenge state must be deleted (single-use).
        assert await env.challenge_store.load(user_id=str(user.id), purpose="login") is None

    @pytest.mark.asyncio
    async def test_reused_challenge_token_is_rejected(
        self,
        mfa_service: MfaService,
        env: MfaServiceTestEnvironment,
    ) -> None:
        user = _make_enrolled_user(env)
        challenge = await mfa_service.start_login_challenge(
            db_session=env.db, user=user, requested_audience=None
        )
        sent = env.sms.calls[-1]

        await mfa_service.verify_login(
            db_session=env.db,
            challenge_token=challenge.challenge_token,
            code=sent["code"],
            recovery_code=None,
            client_ip="203.0.113.10",
            user_agent="pytest",
        )

        with pytest.raises(MfaServiceError) as info:
            await mfa_service.verify_login(
                db_session=env.db,
                challenge_token=challenge.challenge_token,
                code=sent["code"],
                recovery_code=None,
                client_ip="203.0.113.10",
                user_agent="pytest",
            )
        assert info.value.code in {"challenge_expired", "challenge_reused"}

    @pytest.mark.asyncio
    async def test_wrong_code_does_not_issue_tokens_and_increments_attempts(
        self,
        mfa_service: MfaService,
        env: MfaServiceTestEnvironment,
    ) -> None:
        user = _make_enrolled_user(env)
        challenge = await mfa_service.start_login_challenge(
            db_session=env.db, user=user, requested_audience=None
        )

        with pytest.raises(MfaServiceError) as info:
            await mfa_service.verify_login(
                db_session=env.db,
                challenge_token=challenge.challenge_token,
                code="000000",
                recovery_code=None,
                client_ip="203.0.113.10",
                user_agent="pytest",
            )
        assert info.value.code == "invalid_code"

        challenge_state = await env.challenge_store.load(user_id=str(user.id), purpose="login")
        assert challenge_state is not None
        assert challenge_state.attempt_count == 1

    @pytest.mark.asyncio
    async def test_payload_must_include_either_code_or_recovery_code(
        self,
        mfa_service: MfaService,
        env: MfaServiceTestEnvironment,
    ) -> None:
        user = _make_enrolled_user(env)
        challenge = await mfa_service.start_login_challenge(
            db_session=env.db, user=user, requested_audience=None
        )

        with pytest.raises(MfaServiceError):
            await mfa_service.verify_login(
                db_session=env.db,
                challenge_token=challenge.challenge_token,
                code=None,
                recovery_code=None,
                client_ip="203.0.113.10",
                user_agent="pytest",
            )


class TestVerifyLoginWithRecoveryCode:
    """Recovery codes are single-use and can substitute for SMS."""

    @pytest.mark.asyncio
    async def test_recovery_code_succeeds_and_marks_code_used(
        self,
        mfa_service: MfaService,
        env: MfaServiceTestEnvironment,
    ) -> None:
        user = _make_enrolled_user(env)
        token = await env.mint_action_token(user_id=str(user.id), action="enable_mfa")
        # Reset enabled state so enable_mfa returns plaintext recovery codes.
        user.mfa_enabled = False
        user.mfa_primary_method = None
        enable = await mfa_service.enable_mfa(
            db_session=env.db,
            user_id=str(user.id),
            action_token=token,
        )
        plaintext_code = enable.recovery_codes[0]

        challenge = await mfa_service.start_login_challenge(
            db_session=env.db, user=user, requested_audience=None
        )

        result = await mfa_service.verify_login(
            db_session=env.db,
            challenge_token=challenge.challenge_token,
            code=None,
            recovery_code=plaintext_code,
            client_ip="203.0.113.10",
            user_agent="pytest",
        )

        assert result.method_used == "recovery_code"
        assert result.token_pair.access_token

        # Used-at is set on the consumed row only.
        used_rows = [
            row
            for row in env.db.recovery_codes.values()
            if row.user_id == user.id and row.used_at is not None
        ]
        assert len(used_rows) == 1

    @pytest.mark.asyncio
    async def test_recovery_code_cannot_be_reused(
        self,
        mfa_service: MfaService,
        env: MfaServiceTestEnvironment,
    ) -> None:
        user = _make_enrolled_user(env)
        user.mfa_enabled = False
        user.mfa_primary_method = None
        token = await env.mint_action_token(user_id=str(user.id), action="enable_mfa")
        enable = await mfa_service.enable_mfa(
            db_session=env.db,
            user_id=str(user.id),
            action_token=token,
        )
        plaintext = enable.recovery_codes[0]

        first_challenge = await mfa_service.start_login_challenge(
            db_session=env.db, user=user, requested_audience=None
        )
        await mfa_service.verify_login(
            db_session=env.db,
            challenge_token=first_challenge.challenge_token,
            code=None,
            recovery_code=plaintext,
            client_ip="203.0.113.10",
            user_agent="pytest",
        )

        second_challenge = await mfa_service.start_login_challenge(
            db_session=env.db, user=user, requested_audience=None
        )
        with pytest.raises(MfaServiceError) as info:
            await mfa_service.verify_login(
                db_session=env.db,
                challenge_token=second_challenge.challenge_token,
                code=None,
                recovery_code=plaintext,
                client_ip="203.0.113.10",
                user_agent="pytest",
            )
        assert info.value.code == "invalid_recovery_code"


class TestResendLoginCode:
    """Resend issues a new SMS code keyed to the same active challenge."""

    @pytest.mark.asyncio
    async def test_resend_replaces_active_code_and_resets_attempt_counter(
        self,
        mfa_service: MfaService,
        env: MfaServiceTestEnvironment,
    ) -> None:
        user = _make_enrolled_user(env)
        challenge = await mfa_service.start_login_challenge(
            db_session=env.db, user=user, requested_audience=None
        )
        first_code = env.sms.calls[-1]["code"]

        # Burn one wrong attempt to verify the counter resets after resend.
        with pytest.raises(MfaServiceError):
            await mfa_service.verify_login(
                db_session=env.db,
                challenge_token=challenge.challenge_token,
                code="000000",
                recovery_code=None,
                client_ip="203.0.113.10",
                user_agent="pytest",
            )

        await mfa_service.resend_login_code(
            db_session=env.db,
            challenge_token=challenge.challenge_token,
        )

        latest_code = env.sms.calls[-1]["code"]
        assert latest_code != first_code

        challenge_state = await env.challenge_store.load(user_id=str(user.id), purpose="login")
        assert challenge_state is not None
        assert challenge_state.attempt_count == 0

    @pytest.mark.asyncio
    async def test_resend_rate_limit(
        self,
        mfa_service: MfaService,
        env: MfaServiceTestEnvironment,
    ) -> None:
        user = _make_enrolled_user(env)
        challenge = await mfa_service.start_login_challenge(
            db_session=env.db, user=user, requested_audience=None
        )

        # First N resends succeed.
        for _ in range(env.settings.mfa.rate_limits.sms_resend_per_challenge):
            await mfa_service.resend_login_code(
                db_session=env.db,
                challenge_token=challenge.challenge_token,
            )

        with pytest.raises(MfaServiceError) as info:
            await mfa_service.resend_login_code(
                db_session=env.db,
                challenge_token=challenge.challenge_token,
            )
        assert info.value.code == "rate_limited"
