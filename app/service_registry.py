"""Centralized service registry with cache invalidation support.

Replaces bare ``@lru_cache`` on singleton factory functions so that cached
instances can be invalidated at runtime — e.g. after a configuration change,
credential rotation, or Redis failover — without restarting the process.

Usage
-----
Each ``get_*()`` factory delegates to the global registry via
:func:`get_or_create`.  To force re-creation of every cached service and
infrastructure dependency, call :func:`clear_all` (sync) or
:func:`async_clear_all` (async, with dispose hooks for connections).

>>> from app.service_registry import get_or_create, clear_all
>>> svc = get_or_create("my_service", lambda: MyService(...))
>>> clear_all()  # next call to get_or_create will rebuild
"""

from __future__ import annotations

import functools
import logging
from collections.abc import Callable, Coroutine
from threading import Lock
from typing import Any, NamedTuple, TypeVar

logger = logging.getLogger(__name__)

DisposeCallback = Callable[[], Coroutine[Any, Any, None]]
F = TypeVar("F", bound=Callable[..., Any])


class ServiceRegistry:
    """Thread-safe lazy-singleton cache with explicit invalidation.

    Each entry is identified by a string key.  The first call to
    :meth:`get_or_create` for a given key invokes the factory and caches
    the result.  Subsequent calls return the cached instance until
    :meth:`clear` is called.

    Optional *dispose* callbacks (async) can be registered per key to
    perform graceful cleanup (e.g. closing connection pools) during
    :meth:`async_clear`.
    """

    def __init__(self) -> None:
        self._instances: dict[str, Any] = {}
        self._dispose_callbacks: dict[str, DisposeCallback] = {}
        self._lock = Lock()

    def get_or_create(self, key: str, factory: Callable[[], Any]) -> Any:
        """Return the cached instance for *key*, creating it via *factory* if absent."""
        # Fast path: already cached (no lock)
        instance = self._instances.get(key)
        if instance is not None:
            return instance

        with self._lock:
            # Double-checked locking
            instance = self._instances.get(key)
            if instance is not None:
                return instance
            instance = factory()
            self._instances[key] = instance
            return instance

    def register_dispose(self, key: str, callback: DisposeCallback) -> None:
        """Register an async callback invoked when *key* is cleared.

        Useful for closing Redis connections, disposing SQLAlchemy engines,
        or any other async teardown.  Only one callback per key is stored;
        a later registration replaces the previous one.
        """
        self._dispose_callbacks[key] = callback

    def is_cached(self, key: str) -> bool:
        """Return ``True`` if *key* currently has a cached instance."""
        return key in self._instances

    def clear(self, key: str | None = None) -> None:
        """Synchronously drop cached instances.

        If *key* is ``None``, all entries are cleared.  This does **not**
        invoke dispose callbacks — use :meth:`async_clear` when graceful
        teardown is required.
        """
        with self._lock:
            if key is None:
                self._instances.clear()
                self._dispose_callbacks.clear()
            else:
                self._instances.pop(key, None)
                self._dispose_callbacks.pop(key, None)

    async def async_clear(self, key: str | None = None) -> None:
        """Clear cached instances, awaiting dispose callbacks first.

        Errors in individual dispose callbacks are logged but do not
        prevent other callbacks from running or the cache from being
        cleared.
        """
        with self._lock:
            if key is not None:
                callback = self._dispose_callbacks.pop(key, None)
                self._instances.pop(key, None)
                callbacks_to_run = [(key, callback)] if callback else []
            else:
                callbacks_to_run = list(self._dispose_callbacks.items())
                self._instances.clear()
                self._dispose_callbacks.clear()

        for cb_key, callback in callbacks_to_run:
            try:
                await callback()
            except Exception:
                logger.warning(
                    "Dispose callback failed for '%s'; continuing teardown",
                    cb_key,
                    exc_info=True,
                )


# ---------------------------------------------------------------------------
# Global registry instance and convenience helpers
# ---------------------------------------------------------------------------

registry = ServiceRegistry()
"""Module-level singleton used by all ``get_*()`` factory functions."""


def get_or_create(key: str, factory: Callable[[], Any]) -> Any:
    """Convenience wrapper around :meth:`ServiceRegistry.get_or_create`."""
    return registry.get_or_create(key, factory)


def clear_all(key: str | None = None) -> None:
    """Synchronously invalidate cached instances in the global registry."""
    registry.clear(key)


async def async_clear_all(key: str | None = None) -> None:
    """Async invalidate with dispose callbacks in the global registry."""
    await registry.async_clear(key)


# ---------------------------------------------------------------------------
# Decorator: drop-in replacement for @lru_cache on factory functions
# ---------------------------------------------------------------------------


class _CacheInfo(NamedTuple):
    """Mimics :func:`functools.lru_cache` cache_info for backward compat."""

    hits: int
    misses: int
    maxsize: int | None
    currsize: int


def service_cached(fn: F) -> F:
    """Decorator replacing ``@lru_cache`` on singleton factory functions.

    The decorated function behaves identically to an ``@lru_cache``-wrapped
    function from the caller's perspective, but delegates storage to the
    global :data:`registry`.  It exposes ``.cache_clear()`` and
    ``.cache_info()`` for backward compatibility with existing test code
    that calls ``get_settings.cache_clear()``.

    The registry key is derived from the fully-qualified function name.
    """
    key = f"{fn.__module__}.{fn.__qualname__}"

    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:  # noqa: ARG001
        return registry.get_or_create(key, fn)

    def cache_clear() -> None:
        registry.clear(key)

    def cache_info() -> _CacheInfo:
        return _CacheInfo(
            hits=0,
            misses=0,
            maxsize=None,
            currsize=1 if registry.is_cached(key) else 0,
        )

    wrapper.cache_clear = cache_clear  # type: ignore[attr-defined]
    wrapper.cache_info = cache_info  # type: ignore[attr-defined]
    wrapper._registry_key = key  # type: ignore[attr-defined]
    return wrapper  # type: ignore[return-value]
