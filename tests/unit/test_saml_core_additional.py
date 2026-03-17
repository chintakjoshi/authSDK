"""Additional unit tests for SAML core helpers."""

from __future__ import annotations

from dataclasses import dataclass
from types import MethodType, ModuleType, SimpleNamespace
from typing import Any

import pytest
from fastapi import Request

from app.core.saml import (
    SamlAssertion,
    SamlCore,
    SamlProtocolError,
    _build_saml_settings_from_config,
    build_saml_request_data,
    get_saml_core,
)


@dataclass
class _AuthStub:
    """Configurable SAML auth stub."""

    errors: list[str]
    authenticated: bool
    name_id: str
    attributes: dict[str, list[str]]
    login_url_value: str = "https://idp.example.com/login"
    raise_on_login: bool = False
    raise_on_process: bool = False

    def login(self, return_to: str | None) -> str:
        del return_to
        if self.raise_on_login:
            raise RuntimeError("login failed")
        return self.login_url_value

    def process_response(self) -> None:
        if self.raise_on_process:
            raise ValueError("bad assertion")

    def get_errors(self) -> list[str]:
        return self.errors

    def is_authenticated(self) -> bool:
        return self.authenticated

    def get_nameid(self) -> str:
        return self.name_id

    def get_attributes(self) -> dict[str, list[str]]:
        return self.attributes


class _SettingsStub:
    """Configurable python3-saml settings stub."""

    def __init__(self, metadata: str = "<xml/>", errors: list[str] | None = None) -> None:
        self.metadata = metadata
        self.errors = errors or []

    def get_sp_metadata(self) -> str:
        return self.metadata

    def validate_metadata(self, metadata: str) -> list[str]:
        del metadata
        return self.errors


def _core() -> SamlCore:
    return SamlCore(settings_data={"strict": True})


def test_login_url_success_and_failure() -> None:
    """SAML login URL generation returns the IdP URL and maps failures."""
    core = _core()

    def _build_auth(self: SamlCore, request_data: dict[str, Any]) -> _AuthStub:
        del request_data
        return _AuthStub([], True, "", {})

    core._build_auth = MethodType(_build_auth, core)  # type: ignore[assignment]
    assert core.login_url({}, "relay-state") == "https://idp.example.com/login"

    def _build_bad_auth(self: SamlCore, request_data: dict[str, Any]) -> _AuthStub:
        del request_data
        return _AuthStub([], True, "", {}, raise_on_login=True)

    core._build_auth = MethodType(_build_bad_auth, core)  # type: ignore[assignment]
    with pytest.raises(SamlProtocolError) as exc_info:
        core.login_url({}, "relay-state")
    assert exc_info.value.status_code == 400


def test_parse_assertion_extracts_email_and_verified_state() -> None:
    """Assertion parsing normalizes NameID, email, and email_verified attributes."""
    core = _core()

    def _build_auth(self: SamlCore, request_data: dict[str, Any]) -> _AuthStub:
        del request_data
        return _AuthStub(
            errors=[],
            authenticated=True,
            name_id="nameid@example.com",
            attributes={
                "email": ["user@example.com"],
                "emailVerified": ["true"],
            },
        )

    core._build_auth = MethodType(_build_auth, core)  # type: ignore[assignment]
    assertion = core.parse_assertion({})
    assert assertion == SamlAssertion(
        provider_user_id="nameid@example.com",
        email="user@example.com",
        email_verified=True,
    )


def test_parse_assertion_rejects_missing_identity_or_email() -> None:
    """Malformed assertions without identity information fail closed."""
    core = _core()

    def _build_auth(self: SamlCore, request_data: dict[str, Any]) -> _AuthStub:
        del request_data
        return _AuthStub(errors=[], authenticated=True, name_id="", attributes={})

    core._build_auth = MethodType(_build_auth, core)  # type: ignore[assignment]
    with pytest.raises(SamlProtocolError) as exc_info:
        core.parse_assertion({})
    assert exc_info.value.status_code == 401


def test_metadata_xml_success_and_validation_failure() -> None:
    """Metadata generation returns XML and rejects invalid output."""
    core = _core()

    def _build_settings(self: SamlCore) -> _SettingsStub:
        return _SettingsStub(metadata="<EntityDescriptor/>")

    core._build_settings = MethodType(_build_settings, core)  # type: ignore[assignment]
    assert core.metadata_xml() == "<EntityDescriptor/>"

    def _build_bad_settings(self: SamlCore) -> _SettingsStub:
        return _SettingsStub(metadata="<EntityDescriptor/>", errors=["bad"])

    core._build_settings = MethodType(_build_bad_settings, core)  # type: ignore[assignment]
    with pytest.raises(SamlProtocolError) as exc_info:
        core.metadata_xml()
    assert exc_info.value.status_code == 500


def test_build_saml_request_data_uses_expected_host_scheme_and_ports() -> None:
    """FastAPI requests convert into the python3-saml request shape."""
    https_request = Request(
        {
            "type": "http",
            "scheme": "https",
            "method": "GET",
            "path": "/auth/saml/callback",
            "query_string": b"SAMLResponse=fake",
            "headers": [(b"host", b"service.local")],
            "server": ("service.local", 443),
            "client": ("127.0.0.1", 12345),
        }
    )
    http_request = Request(
        {
            "type": "http",
            "scheme": "http",
            "method": "GET",
            "path": "/auth/saml/callback",
            "query_string": b"",
            "headers": [(b"host", b"service.local:8080")],
            "server": ("service.local", 8080),
            "client": ("127.0.0.1", 12345),
        }
    )

    https_data = build_saml_request_data(https_request)
    http_data = build_saml_request_data(http_request, get_data={"RelayState": "abc"})

    assert https_data["https"] == "on"
    assert https_data["server_port"] == "443"
    assert http_data["https"] == "off"
    assert http_data["get_data"] == {"RelayState": "abc"}


def test_build_saml_settings_and_cached_dependency(monkeypatch) -> None:
    """SAML settings and cached core are sourced from app configuration."""
    fake_settings = SimpleNamespace(
        app=SimpleNamespace(environment="development"),
        saml=SimpleNamespace(
            sp_entity_id="sp-entity",
            sp_acs_url="https://service.local/auth/saml/callback",
            sp_x509_cert=SimpleNamespace(get_secret_value=lambda: "sp-cert"),
            sp_private_key=SimpleNamespace(get_secret_value=lambda: "sp-key"),
            idp_entity_id="idp-entity",
            idp_sso_url="https://idp.example.com/sso",
            idp_x509_cert=SimpleNamespace(get_secret_value=lambda: "idp-cert"),
        ),
    )
    monkeypatch.setattr("app.core.saml.get_settings", lambda: fake_settings)

    settings_data = _build_saml_settings_from_config()
    assert settings_data["debug"] is True
    assert settings_data["sp"]["entityId"] == "sp-entity"

    get_saml_core.cache_clear()
    core = get_saml_core()
    assert isinstance(core, SamlCore)
    get_saml_core.cache_clear()


def test_build_auth_and_settings_use_onelogin_imports(monkeypatch) -> None:
    """SAML core builds python3-saml auth/settings objects from imported modules."""
    core = _core()
    fake_auth_module = ModuleType("onelogin.saml2.auth")
    fake_settings_module = ModuleType("onelogin.saml2.settings")

    class _ImportedAuth:
        def __init__(self, request_data, old_settings):  # type: ignore[no-untyped-def]
            self.request_data = request_data
            self.old_settings = old_settings

    class _ImportedSettings:
        def __init__(self, settings):  # type: ignore[no-untyped-def]
            self.settings = settings

    fake_auth_module.OneLogin_Saml2_Auth = _ImportedAuth  # type: ignore[attr-defined]
    fake_settings_module.OneLogin_Saml2_Settings = _ImportedSettings  # type: ignore[attr-defined]
    monkeypatch.setitem(__import__("sys").modules, "onelogin.saml2.auth", fake_auth_module)
    monkeypatch.setitem(__import__("sys").modules, "onelogin.saml2.settings", fake_settings_module)

    auth = core._build_auth({"https": "on"})
    settings = core._build_settings()
    assert auth.request_data == {"https": "on"}
    assert settings.settings == {"strict": True}
