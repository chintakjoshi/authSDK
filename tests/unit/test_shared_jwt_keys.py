"""Unit tests for shared Docker Compose JWT key bootstrapping."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from app.runtime.shared_jwt_keys import (
    JWTKeyMaterial,
    export_jwt_environment,
    load_jwt_key_material,
)


def test_load_jwt_key_material_prefers_explicit_environment(tmp_path: Path) -> None:
    """Explicit JWT environment variables take precedence over shared key files."""
    key_dir = tmp_path / "jwt"
    material = load_jwt_key_material(
        key_dir=key_dir,
        environ={
            "JWT__PRIVATE_KEY_PEM": "private-from-env",
            "JWT__PUBLIC_KEY_PEM": "public-from-env",
        },
    )

    assert material == JWTKeyMaterial(
        private_key_pem="private-from-env",
        public_key_pem="public-from-env",
    )
    assert not key_dir.exists()


def test_load_jwt_key_material_rejects_partial_environment(tmp_path: Path) -> None:
    """Boot should fail fast when only one JWT key environment variable is present."""
    with pytest.raises(ValueError, match="Both JWT__PRIVATE_KEY_PEM and JWT__PUBLIC_KEY_PEM"):
        load_jwt_key_material(
            key_dir=tmp_path / "jwt",
            environ={"JWT__PRIVATE_KEY_PEM": "private-only"},
        )


def test_load_jwt_key_material_generates_and_reuses_shared_files(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Missing shared files are generated once and reused on later loads."""
    generated_pairs = iter(
        [
            ("private-generated-1", "public-generated-1"),
            ("private-generated-2", "public-generated-2"),
        ]
    )
    monkeypatch.setattr(
        "app.runtime.shared_jwt_keys.generate_rsa_keypair",
        lambda: next(generated_pairs),
    )

    key_dir = tmp_path / "jwt"
    first = load_jwt_key_material(key_dir=key_dir, environ={}, generate_if_missing=True)
    second = load_jwt_key_material(key_dir=key_dir, environ={}, generate_if_missing=True)

    assert first == JWTKeyMaterial(
        private_key_pem="private-generated-1",
        public_key_pem="public-generated-1",
    )
    assert second == first
    assert (key_dir / "jwt_private.pem").read_text(encoding="utf-8") == "private-generated-1"
    assert (key_dir / "jwt_public.pem").read_text(encoding="utf-8") == "public-generated-1"


def test_export_jwt_environment_loads_from_shared_files(tmp_path: Path) -> None:
    """Services can export JWT environment variables from shared key files."""
    key_dir = tmp_path / "jwt"
    key_dir.mkdir()
    (key_dir / "jwt_private.pem").write_text("private-from-file", encoding="utf-8")
    (key_dir / "jwt_public.pem").write_text("public-from-file", encoding="utf-8")
    environ: dict[str, str] = {}

    material = export_jwt_environment(key_dir=key_dir, environ=environ)

    assert material == JWTKeyMaterial(
        private_key_pem="private-from-file",
        public_key_pem="public-from-file",
    )
    assert environ == {
        "JWT__PRIVATE_KEY_PEM": "private-from-file",
        "JWT__PUBLIC_KEY_PEM": "public-from-file",
    }


def test_module_cli_init_only_generates_shared_files(tmp_path: Path) -> None:
    """The module entrypoint should generate shared files when invoked with python -m."""
    key_dir = tmp_path / "jwt"
    child_environ = dict(os.environ)
    child_environ.pop("JWT__PRIVATE_KEY_PEM", None)
    child_environ.pop("JWT__PUBLIC_KEY_PEM", None)

    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "app.runtime.shared_jwt_keys",
            "--key-dir",
            str(key_dir),
            "--init-only",
        ],
        check=False,
        capture_output=True,
        text=True,
        env=child_environ,
    )

    assert completed.returncode == 0, completed.stderr
    assert (key_dir / "jwt_private.pem").is_file()
    assert (key_dir / "jwt_public.pem").is_file()


def test_docker_compose_uses_shared_jwt_bootstrap_service() -> None:
    """Compose should centralize fallback JWT key material across services."""
    compose_text = Path("docker/docker-compose.yml").read_text(encoding="utf-8")

    assert "jwt-key-bootstrap:" in compose_text
    assert "shared_jwt_keys:/var/run/auth-service/jwt" in compose_text
    assert "condition: service_completed_successfully" in compose_text
    assert "app.runtime.shared_jwt_keys" in compose_text
    assert "openssl genpkey" not in compose_text
