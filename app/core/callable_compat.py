"""Helpers for cached callable-parameter inspection in compatibility shims."""

from __future__ import annotations

import inspect
from functools import lru_cache


def _inspect_parameter_names(callable_object: object) -> frozenset[str] | None:
    """Inspect one callable and return its accepted parameter names."""
    try:
        signature = inspect.signature(callable_object)
    except (TypeError, ValueError):
        return None
    if signature is None:
        return None
    return frozenset(signature.parameters)


@lru_cache(maxsize=256)
def _inspect_parameter_names_cached(cache_key: object) -> frozenset[str] | None:
    """Cache parameter-name inspection for stable callable implementations."""
    return _inspect_parameter_names(cache_key)


def get_callable_parameter_names(callable_object: object) -> frozenset[str] | None:
    """Return cached parameter names, normalizing bound methods to a shared key."""
    cache_key = getattr(callable_object, "__func__", callable_object)
    try:
        hash(cache_key)
    except TypeError:
        return _inspect_parameter_names(callable_object)
    return _inspect_parameter_names_cached(cache_key)


def add_supported_kwarg(
    kwargs: dict[str, object],
    *,
    supported_parameters: frozenset[str] | None,
    name: str,
    value: object | None,
) -> None:
    """Add one optional kwarg only when the callee advertises support for it."""
    if value is not None and supported_parameters is not None and name in supported_parameters:
        kwargs[name] = value


def clear_callable_parameter_name_cache() -> None:
    """Clear cached callable parameter names for test isolation."""
    _inspect_parameter_names_cached.cache_clear()
