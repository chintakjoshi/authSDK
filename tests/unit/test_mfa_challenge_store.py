"""Unit tests for the Redis-backed MFA challenge store."""

from __future__ import annotations

from uuid import uuid4

import pytest
from redis.exceptions import RedisError

from app.core.mfa.challenge import (
    ChallengeState,
    MfaChallengePurpose,
    MfaChallengeStore,
    MfaChallengeStoreError,
)


class _FakeRedis:
    """In-memory Redis double with hash, expire, and delete support."""

    def __init__(self) -> None:
        self.hashes: dict[str, dict[str, str]] = {}
        self.ttls: dict[str, int] = {}
        self.fail_next: Exception | None = None

    def _guard(self) -> None:
        if self.fail_next is not None:
            error = self.fail_next
            self.fail_next = None
            raise error

    async def hset(self, key: str, *, mapping: dict[str, str]) -> int:
        self._guard()
        current = self.hashes.setdefault(key, {})
        added = sum(1 for field in mapping if field not in current)
        current.update({k: str(v) for k, v in mapping.items()})
        return added

    async def hgetall(self, key: str) -> dict[str, str]:
        self._guard()
        return dict(self.hashes.get(key, {}))

    async def hincrby(self, key: str, field: str, amount: int) -> int:
        self._guard()
        current = self.hashes.setdefault(key, {})
        new_value = int(current.get(field, "0")) + amount
        current[field] = str(new_value)
        return new_value

    async def delete(self, *keys: str) -> int:
        self._guard()
        removed = 0
        for key in keys:
            if key in self.hashes:
                del self.hashes[key]
                removed += 1
            self.ttls.pop(key, None)
        return removed

    async def expire(self, key: str, seconds: int) -> bool:
        self._guard()
        if key not in self.hashes:
            return False
        self.ttls[key] = seconds
        return True


@pytest.fixture()
def fake_redis() -> _FakeRedis:
    return _FakeRedis()


@pytest.fixture()
def store(fake_redis: _FakeRedis) -> MfaChallengeStore:
    return MfaChallengeStore(redis_client=fake_redis)


async def _store_login_challenge(
    store: MfaChallengeStore,
    *,
    user_id: str,
    code_hash: str = "abc",
    jti: str = "jti-1",
    audience: str | list[str] | None = None,
    ttl: int = 600,
) -> None:
    await store.store(
        user_id=user_id,
        purpose="login",
        method="sms",
        code_hash=code_hash,
        jti=jti,
        audience=audience,
        ttl_seconds=ttl,
    )


class TestStoreAndLoad:
    """Basic hash payload shape and TTL semantics."""

    async def test_store_writes_hash_and_sets_ttl(
        self, store: MfaChallengeStore, fake_redis: _FakeRedis
    ) -> None:
        user_id = str(uuid4())

        await _store_login_challenge(store, user_id=user_id, ttl=600)

        key = f"mfa:challenge:login:{user_id}"
        assert fake_redis.hashes[key]["code_hash"] == "abc"
        assert fake_redis.hashes[key]["attempt_count"] == "0"
        assert fake_redis.hashes[key]["jti"] == "jti-1"
        assert fake_redis.hashes[key]["method"] == "sms"
        assert fake_redis.hashes[key]["purpose"] == "login"
        assert fake_redis.ttls[key] == 600

    async def test_load_returns_state(self, store: MfaChallengeStore) -> None:
        user_id = str(uuid4())
        await _store_login_challenge(store, user_id=user_id, code_hash="hashv", jti="jti-2")

        state = await store.load(user_id=user_id, purpose="login")

        assert isinstance(state, ChallengeState)
        assert state.user_id == user_id
        assert state.purpose == "login"
        assert state.method == "sms"
        assert state.code_hash == "hashv"
        assert state.jti == "jti-2"
        assert state.attempt_count == 0

    async def test_load_returns_none_when_missing(self, store: MfaChallengeStore) -> None:
        assert await store.load(user_id=str(uuid4()), purpose="login") is None

    async def test_audience_list_is_preserved(self, store: MfaChallengeStore) -> None:
        user_id = str(uuid4())
        await _store_login_challenge(
            store, user_id=user_id, audience=["auth-service", "reporting-service"]
        )

        state = await store.load(user_id=user_id, purpose="login")

        assert state is not None
        assert state.audience == ["auth-service", "reporting-service"]


class TestOverwriteAndSingleUse:
    """Re-issuing must overwrite, and delete makes the challenge single-use."""

    async def test_store_overwrites_prior_payload(
        self, store: MfaChallengeStore, fake_redis: _FakeRedis
    ) -> None:
        user_id = str(uuid4())
        await _store_login_challenge(store, user_id=user_id, code_hash="first", jti="jti-a")
        await _store_login_challenge(store, user_id=user_id, code_hash="second", jti="jti-b")

        state = await store.load(user_id=user_id, purpose="login")
        assert state is not None
        assert state.code_hash == "second"
        assert state.jti == "jti-b"
        assert state.attempt_count == 0

    async def test_delete_removes_state(
        self, store: MfaChallengeStore, fake_redis: _FakeRedis
    ) -> None:
        user_id = str(uuid4())
        await _store_login_challenge(store, user_id=user_id)

        await store.delete(user_id=user_id, purpose="login")

        assert await store.load(user_id=user_id, purpose="login") is None


class TestAttemptCounter:
    """Attempt counter is incremented atomically and observable via load()."""

    async def test_increment_returns_new_count(self, store: MfaChallengeStore) -> None:
        user_id = str(uuid4())
        await _store_login_challenge(store, user_id=user_id)

        first = await store.increment_attempts(user_id=user_id, purpose="login")
        second = await store.increment_attempts(user_id=user_id, purpose="login")

        assert first == 1
        assert second == 2

        state = await store.load(user_id=user_id, purpose="login")
        assert state is not None
        assert state.attempt_count == 2


class TestJtiBinding:
    """jti binding makes the signed challenge JWT single-use via Redis."""

    async def test_assert_jti_matches_accepts_matching_claim(
        self, store: MfaChallengeStore
    ) -> None:
        user_id = str(uuid4())
        await _store_login_challenge(store, user_id=user_id, jti="expected")
        state = await store.load(user_id=user_id, purpose="login")

        assert state is not None
        store.assert_jti_matches(state=state, claimed_jti="expected")

    async def test_assert_jti_matches_rejects_mismatched_claim(
        self, store: MfaChallengeStore
    ) -> None:
        user_id = str(uuid4())
        await _store_login_challenge(store, user_id=user_id, jti="expected")
        state = await store.load(user_id=user_id, purpose="login")

        assert state is not None
        with pytest.raises(MfaChallengeStoreError) as info:
            store.assert_jti_matches(state=state, claimed_jti="different")
        assert info.value.code == "challenge_reused"

    async def test_assert_jti_rejects_empty_claim(self, store: MfaChallengeStore) -> None:
        user_id = str(uuid4())
        await _store_login_challenge(store, user_id=user_id, jti="expected")
        state = await store.load(user_id=user_id, purpose="login")

        assert state is not None
        with pytest.raises(MfaChallengeStoreError):
            store.assert_jti_matches(state=state, claimed_jti="")


class TestPurposeIsolation:
    """Different purposes for the same user must not collide."""

    @pytest.mark.parametrize(
        "purpose_a, purpose_b",
        [
            ("login", "action"),
            ("login", "phone_verify"),
            ("action", "phone_verify"),
        ],
    )
    async def test_purposes_have_independent_state(
        self,
        store: MfaChallengeStore,
        purpose_a: MfaChallengePurpose,
        purpose_b: MfaChallengePurpose,
    ) -> None:
        user_id = str(uuid4())

        await store.store(
            user_id=user_id,
            purpose=purpose_a,
            method="sms",
            code_hash="code-a",
            jti="jti-a",
            ttl_seconds=600,
        )
        await store.store(
            user_id=user_id,
            purpose=purpose_b,
            method="sms",
            code_hash="code-b",
            jti="jti-b",
            ttl_seconds=600,
        )

        state_a = await store.load(user_id=user_id, purpose=purpose_a)
        state_b = await store.load(user_id=user_id, purpose=purpose_b)

        assert state_a is not None and state_a.code_hash == "code-a"
        assert state_b is not None and state_b.code_hash == "code-b"


class TestFailureMode:
    """Redis backend errors must surface as a well-typed store error."""

    async def test_redis_failure_during_store_is_translated(
        self, store: MfaChallengeStore, fake_redis: _FakeRedis
    ) -> None:
        fake_redis.fail_next = RedisError("boom")

        with pytest.raises(MfaChallengeStoreError) as info:
            await _store_login_challenge(store, user_id=str(uuid4()))
        assert info.value.code == "session_backend_unavailable"

    async def test_redis_failure_during_load_is_translated(
        self, store: MfaChallengeStore, fake_redis: _FakeRedis
    ) -> None:
        fake_redis.fail_next = RedisError("boom")

        with pytest.raises(MfaChallengeStoreError) as info:
            await store.load(user_id=str(uuid4()), purpose="login")
        assert info.value.code == "session_backend_unavailable"
