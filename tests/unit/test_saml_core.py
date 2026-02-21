"""Unit tests for SAML core assertion validation."""

from __future__ import annotations

from types import MethodType
from typing import Any

import pytest

from app.core.saml import SamlCore, SamlProtocolError


class _InvalidSignatureAuthStub:
    """Stub auth object that simulates signature validation failure."""

    def process_response(self) -> None:
        """No-op response processing."""
        return None

    def get_errors(self) -> list[str]:
        """Return validation error list."""
        return ["invalid_signature"]

    def is_authenticated(self) -> bool:
        """Mark assertion as unauthenticated."""
        return False

    def get_nameid(self) -> str:
        """Return empty NameID."""
        return ""

    def get_attributes(self) -> dict[str, list[str]]:
        """Return empty attributes."""
        return {}


class _MalformedAssertionAuthStub:
    """Stub auth object that simulates malformed assertion."""

    def process_response(self) -> None:
        """Raise malformed assertion error."""
        raise ValueError("Malformed SAML assertion")

    def get_errors(self) -> list[str]:
        """Unreachable in this test flow."""
        return []

    def is_authenticated(self) -> bool:
        """Unreachable in this test flow."""
        return False

    def get_nameid(self) -> str:
        """Unreachable in this test flow."""
        return ""

    def get_attributes(self) -> dict[str, list[str]]:
        """Unreachable in this test flow."""
        return {}


def _core() -> SamlCore:
    """Build SAML core with minimal static settings."""
    return SamlCore(settings_data={"strict": True})


def test_parse_assertion_rejects_invalid_signature() -> None:
    """Invalid signature errors map to saml_assertion_invalid."""
    core = _core()

    def _fake_build_auth(self: SamlCore, request_data: dict[str, Any]) -> _InvalidSignatureAuthStub:
        return _InvalidSignatureAuthStub()

    core._build_auth = MethodType(_fake_build_auth, core)  # type: ignore[assignment]
    with pytest.raises(SamlProtocolError) as exc_info:
        core.parse_assertion(request_data={})

    assert exc_info.value.code == "saml_assertion_invalid"
    assert exc_info.value.status_code == 401


def test_parse_assertion_rejects_malformed_response() -> None:
    """Malformed SAML response maps to saml_assertion_invalid."""
    core = _core()

    def _fake_build_auth(
        self: SamlCore, request_data: dict[str, Any]
    ) -> _MalformedAssertionAuthStub:
        return _MalformedAssertionAuthStub()

    core._build_auth = MethodType(_fake_build_auth, core)  # type: ignore[assignment]
    with pytest.raises(SamlProtocolError) as exc_info:
        core.parse_assertion(request_data={})

    assert exc_info.value.code == "saml_assertion_invalid"
    assert exc_info.value.status_code == 401
