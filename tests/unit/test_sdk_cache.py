"""Unit tests for SDK JWKS cache manager behavior."""

from __future__ import annotations

from sdk.cache import JWKSCacheManager


class _AuthClientStub:
    """Auth client stub returning deterministic JWKS payloads."""

    def __init__(self) -> None:
        self.calls = 0

    async def fetch_jwks(self) -> dict[str, list[dict[str, str]]]:
        """Return unique JWKS on each call."""
        self.calls += 1
        return {"keys": [{"kid": f"kid-{self.calls}", "kty": "RSA", "n": "n", "e": "e"}]}


class _FakeClock:
    """Controllable monotonic clock for TTL tests."""

    def __init__(self) -> None:
        self.current = 0.0

    def now(self) -> float:
        """Return current synthetic monotonic time."""
        return self.current


async def test_jwks_cache_reuses_value_within_ttl() -> None:
    """JWKS is fetched once and reused until cache expiration."""
    client = _AuthClientStub()
    clock = _FakeClock()
    cache = JWKSCacheManager(auth_client=client, ttl_seconds=300, now=clock.now)

    jwks_1 = await cache.get_jwks()
    jwks_2 = await cache.get_jwks()

    assert client.calls == 1
    assert jwks_1 == jwks_2


async def test_jwks_cache_refreshes_after_ttl_or_force_refresh() -> None:
    """JWKS refresh occurs after TTL expiration and when forced."""
    client = _AuthClientStub()
    clock = _FakeClock()
    cache = JWKSCacheManager(auth_client=client, ttl_seconds=300, now=clock.now)

    first = await cache.get_jwks()
    clock.current += 301.0
    second = await cache.get_jwks()
    third = await cache.get_jwks(force_refresh=True)

    assert client.calls == 3
    assert first["keys"][0]["kid"] == "kid-1"
    assert second["keys"][0]["kid"] == "kid-2"
    assert third["keys"][0]["kid"] == "kid-3"
