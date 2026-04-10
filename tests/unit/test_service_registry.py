"""Unit tests for the service registry (cache invalidation layer)."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from app.service_registry import ServiceRegistry, clear_all, get_or_create, registry, service_cached


class TestServiceRegistry:
    """Core registry behaviour: lazy creation, caching, and invalidation."""

    def setup_method(self) -> None:
        self.reg = ServiceRegistry()

    def test_get_or_create_calls_factory_once(self) -> None:
        """Factory is invoked exactly once; subsequent calls return the cached instance."""
        factory = MagicMock(return_value="instance-1")

        first = self.reg.get_or_create("svc", factory)
        second = self.reg.get_or_create("svc", factory)

        assert first is second
        factory.assert_called_once()

    def test_get_or_create_different_keys_are_independent(self) -> None:
        """Distinct keys maintain independent cached instances."""
        factory_a = MagicMock(return_value="a")
        factory_b = MagicMock(return_value="b")

        assert self.reg.get_or_create("a", factory_a) == "a"
        assert self.reg.get_or_create("b", factory_b) == "b"
        factory_a.assert_called_once()
        factory_b.assert_called_once()

    def test_clear_invalidates_all_cached_instances(self) -> None:
        """After clear(), the next get_or_create re-invokes the factory."""
        call_count = 0

        def factory() -> str:
            nonlocal call_count
            call_count += 1
            return f"instance-{call_count}"

        first = self.reg.get_or_create("svc", factory)
        self.reg.clear()
        second = self.reg.get_or_create("svc", factory)

        assert first == "instance-1"
        assert second == "instance-2"
        assert call_count == 2

    def test_clear_selective_key(self) -> None:
        """Clearing a specific key only invalidates that entry."""
        factory_a = MagicMock(return_value="a")
        factory_b = MagicMock(return_value="b")

        self.reg.get_or_create("a", factory_a)
        self.reg.get_or_create("b", factory_b)

        self.reg.clear("a")

        # 'a' factory re-invoked, 'b' still cached
        self.reg.get_or_create("a", factory_a)
        self.reg.get_or_create("b", factory_b)

        assert factory_a.call_count == 2
        assert factory_b.call_count == 1

    def test_clear_nonexistent_key_is_noop(self) -> None:
        """Clearing a key that was never registered does not raise."""
        self.reg.clear("nonexistent")  # should not raise

    def test_is_cached(self) -> None:
        """is_cached reports whether a key has a cached instance."""
        assert not self.reg.is_cached("svc")
        self.reg.get_or_create("svc", lambda: "val")
        assert self.reg.is_cached("svc")
        self.reg.clear()
        assert not self.reg.is_cached("svc")


class TestServiceRegistryAsyncCleanup:
    """Registry supports async dispose callbacks on clear."""

    def setup_method(self) -> None:
        self.reg = ServiceRegistry()

    @pytest.mark.asyncio
    async def test_async_clear_invokes_dispose_callbacks(self) -> None:
        """Registered dispose callbacks are awaited during async_clear."""
        disposed: list[str] = []

        async def dispose_redis() -> None:
            disposed.append("redis")

        async def dispose_engine() -> None:
            disposed.append("engine")

        self.reg.get_or_create("redis", lambda: "redis-client")
        self.reg.register_dispose("redis", dispose_redis)

        self.reg.get_or_create("engine", lambda: "engine-obj")
        self.reg.register_dispose("engine", dispose_engine)

        await self.reg.async_clear()

        assert "redis" in disposed
        assert "engine" in disposed
        assert not self.reg.is_cached("redis")
        assert not self.reg.is_cached("engine")

    @pytest.mark.asyncio
    async def test_async_clear_handles_dispose_errors_gracefully(self) -> None:
        """Dispose errors are logged but do not prevent other disposals."""
        disposed: list[str] = []

        async def failing_dispose() -> None:
            raise RuntimeError("connection already closed")

        async def good_dispose() -> None:
            disposed.append("good")

        self.reg.get_or_create("bad", lambda: "bad-client")
        self.reg.register_dispose("bad", failing_dispose)

        self.reg.get_or_create("good", lambda: "good-client")
        self.reg.register_dispose("good", good_dispose)

        # Should not raise despite the failing dispose
        await self.reg.async_clear()

        assert "good" in disposed
        assert not self.reg.is_cached("bad")
        assert not self.reg.is_cached("good")

    @pytest.mark.asyncio
    async def test_async_clear_selective_key(self) -> None:
        """async_clear with a key only disposes and clears that entry."""
        disposed: list[str] = []

        async def dispose_a() -> None:
            disposed.append("a")

        async def dispose_b() -> None:
            disposed.append("b")

        self.reg.get_or_create("a", lambda: "a-val")
        self.reg.register_dispose("a", dispose_a)
        self.reg.get_or_create("b", lambda: "b-val")
        self.reg.register_dispose("b", dispose_b)

        await self.reg.async_clear("a")

        assert disposed == ["a"]
        assert not self.reg.is_cached("a")
        assert self.reg.is_cached("b")

    def test_register_dispose_without_cached_entry_is_accepted(self) -> None:
        """Registering dispose before creation is allowed (for pre-registration)."""

        async def dispose() -> None:
            pass

        # Should not raise
        self.reg.register_dispose("future", dispose)


class TestModuleLevelAPI:
    """Module-level convenience functions delegate to the global registry."""

    def setup_method(self) -> None:
        clear_all()

    def teardown_method(self) -> None:
        clear_all()

    def test_get_or_create_module_level(self) -> None:
        """Module-level get_or_create uses the global registry."""
        factory = MagicMock(return_value="singleton")

        first = get_or_create("test-key", factory)
        second = get_or_create("test-key", factory)

        assert first is second
        factory.assert_called_once()

    def test_clear_all_resets_global_registry(self) -> None:
        """clear_all invalidates everything in the global registry."""
        call_count = 0

        def factory() -> str:
            nonlocal call_count
            call_count += 1
            return f"v{call_count}"

        first = get_or_create("k", factory)
        clear_all()
        second = get_or_create("k", factory)

        assert first == "v1"
        assert second == "v2"

    def test_global_registry_is_singleton(self) -> None:
        """The module-level registry object is a true singleton."""
        assert registry is registry


class TestServiceCachedDecorator:
    """The @service_cached decorator provides lru_cache-compatible API."""

    def setup_method(self) -> None:
        clear_all()

    def teardown_method(self) -> None:
        clear_all()

    def test_decorated_function_caches_result(self) -> None:
        """Decorated function returns the same instance on repeated calls."""
        call_count = 0

        @service_cached
        def get_thing() -> str:
            nonlocal call_count
            call_count += 1
            return f"thing-{call_count}"

        first = get_thing()
        second = get_thing()
        assert first is second
        assert call_count == 1

    def test_cache_clear_forces_rebuild(self) -> None:
        """cache_clear() causes the next call to re-invoke the factory."""
        call_count = 0

        @service_cached
        def get_widget() -> str:
            nonlocal call_count
            call_count += 1
            return f"widget-{call_count}"

        first = get_widget()
        get_widget.cache_clear()
        second = get_widget()

        assert first == "widget-1"
        assert second == "widget-2"
        assert call_count == 2

    def test_cache_info_reports_currsize(self) -> None:
        """cache_info().currsize reflects whether the entry is cached."""

        @service_cached
        def get_gadget() -> str:
            return "gadget"

        assert get_gadget.cache_info().currsize == 0
        get_gadget()
        assert get_gadget.cache_info().currsize == 1
        get_gadget.cache_clear()
        assert get_gadget.cache_info().currsize == 0

    def test_clear_all_invalidates_decorated_functions(self) -> None:
        """Global clear_all() invalidates entries created by @service_cached."""
        call_count = 0

        @service_cached
        def get_item() -> str:
            nonlocal call_count
            call_count += 1
            return f"item-{call_count}"

        get_item()
        clear_all()
        second = get_item()

        assert second == "item-2"

    def test_preserves_function_metadata(self) -> None:
        """Decorated function preserves __name__ and __doc__."""

        @service_cached
        def get_fancy_service() -> str:
            """Build fancy service."""
            return "fancy"

        assert get_fancy_service.__name__ == "get_fancy_service"
        assert get_fancy_service.__doc__ == "Build fancy service."
