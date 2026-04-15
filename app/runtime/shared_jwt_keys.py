"""Shared Docker Compose JWT key bootstrapping utilities."""

from __future__ import annotations

import argparse
import os
import tempfile
from collections.abc import Iterator, Mapping, MutableMapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

_PRIVATE_KEY_ENV_NAME = "JWT__PRIVATE_KEY_PEM"
_PUBLIC_KEY_ENV_NAME = "JWT__PUBLIC_KEY_PEM"
_PRIVATE_KEY_FILE_NAME = "jwt_private.pem"
_PUBLIC_KEY_FILE_NAME = "jwt_public.pem"
_LOCK_FILE_NAME = ".jwt_keys.lock"
_DEFAULT_KEY_DIRECTORY = Path("/var/run/auth-service/jwt")


@dataclass(frozen=True)
class JWTKeyMaterial:
    """PEM-encoded JWT signing material."""

    private_key_pem: str
    public_key_pem: str


def generate_rsa_keypair() -> tuple[str, str]:
    """Generate a fresh PEM-encoded RSA keypair."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    public_key_pem = (
        private_key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("utf-8")
    )
    return private_key_pem, public_key_pem


def load_jwt_key_material(
    *,
    key_dir: Path,
    environ: Mapping[str, str] | None = None,
    generate_if_missing: bool = False,
    private_key_mode: int = 0o600,
    public_key_mode: int = 0o644,
    owner_uid: int | None = None,
    owner_gid: int | None = None,
) -> JWTKeyMaterial:
    """Load JWT key material from environment or a shared key directory."""
    active_environ = os.environ if environ is None else environ
    env_material = _jwt_key_material_from_environment(active_environ)
    if env_material is not None:
        return env_material

    private_key_path = key_dir / _PRIVATE_KEY_FILE_NAME
    public_key_path = key_dir / _PUBLIC_KEY_FILE_NAME
    if private_key_path.is_file() and public_key_path.is_file():
        return _read_jwt_key_material(
            private_key_path=private_key_path, public_key_path=public_key_path
        )
    if not generate_if_missing:
        raise FileNotFoundError(
            "JWT key material was not provided via environment and shared key files were not found."
        )

    key_dir.mkdir(parents=True, exist_ok=True)
    with _exclusive_file_lock(key_dir / _LOCK_FILE_NAME):
        if private_key_path.is_file() and public_key_path.is_file():
            return _read_jwt_key_material(
                private_key_path=private_key_path,
                public_key_path=public_key_path,
            )

        private_key_pem, public_key_pem = generate_rsa_keypair()
        _atomic_write_text(private_key_path, private_key_pem, mode=private_key_mode)
        _atomic_write_text(public_key_path, public_key_pem, mode=public_key_mode)
        _maybe_change_file_owner(private_key_path, uid=owner_uid, gid=owner_gid)
        _maybe_change_file_owner(public_key_path, uid=owner_uid, gid=owner_gid)
        return JWTKeyMaterial(
            private_key_pem=private_key_pem,
            public_key_pem=public_key_pem,
        )


def export_jwt_environment(
    *,
    key_dir: Path,
    environ: MutableMapping[str, str] | None = None,
    generate_if_missing: bool = False,
    private_key_mode: int = 0o600,
    public_key_mode: int = 0o644,
    owner_uid: int | None = None,
    owner_gid: int | None = None,
) -> JWTKeyMaterial:
    """Populate JWT key environment variables from shared key material."""
    target_environ = os.environ if environ is None else environ
    material = load_jwt_key_material(
        key_dir=key_dir,
        environ=target_environ,
        generate_if_missing=generate_if_missing,
        private_key_mode=private_key_mode,
        public_key_mode=public_key_mode,
        owner_uid=owner_uid,
        owner_gid=owner_gid,
    )
    target_environ[_PRIVATE_KEY_ENV_NAME] = material.private_key_pem
    target_environ[_PUBLIC_KEY_ENV_NAME] = material.public_key_pem
    return material


def main(argv: Sequence[str] | None = None) -> int:
    """Bootstrap shared JWT key material and optionally execute a shell command."""
    parser = argparse.ArgumentParser(
        description="Load or create shared JWT key material for Docker Compose services.",
    )
    parser.add_argument(
        "--key-dir",
        type=Path,
        default=_DEFAULT_KEY_DIRECTORY,
        help="Directory that stores shared JWT key material.",
    )
    parser.add_argument(
        "--init-only",
        action="store_true",
        help="Create shared key material when missing, then exit.",
    )
    parser.add_argument(
        "--owner-uid",
        type=int,
        default=None,
        help="Optional file owner UID applied after generating shared key files.",
    )
    parser.add_argument(
        "--owner-gid",
        type=int,
        default=None,
        help="Optional file owner GID applied after generating shared key files.",
    )
    parser.add_argument(
        "--shell-command",
        default=None,
        help="Shell command to execute after exporting JWT environment variables.",
    )
    args = parser.parse_args(argv)

    child_environ = os.environ.copy()
    export_jwt_environment(
        key_dir=args.key_dir,
        environ=child_environ,
        generate_if_missing=args.init_only,
        owner_uid=args.owner_uid,
        owner_gid=args.owner_gid,
    )

    if args.init_only:
        return 0
    if not args.shell_command:
        parser.error("--shell-command is required unless --init-only is provided.")

    os.execvpe("/bin/sh", ["/bin/sh", "-c", args.shell_command], child_environ)
    raise AssertionError("os.execvpe returned unexpectedly")


def _jwt_key_material_from_environment(environ: Mapping[str, str]) -> JWTKeyMaterial | None:
    """Return complete JWT key material from environment, or validate partial configuration."""
    private_key_pem = environ.get(_PRIVATE_KEY_ENV_NAME)
    public_key_pem = environ.get(_PUBLIC_KEY_ENV_NAME)
    if private_key_pem and public_key_pem:
        return JWTKeyMaterial(private_key_pem=private_key_pem, public_key_pem=public_key_pem)
    if private_key_pem or public_key_pem:
        raise ValueError(
            "Both JWT__PRIVATE_KEY_PEM and JWT__PUBLIC_KEY_PEM must be configured together."
        )
    return None


def _read_jwt_key_material(*, private_key_path: Path, public_key_path: Path) -> JWTKeyMaterial:
    """Read PEM-encoded JWT key material from disk."""
    private_key_pem = private_key_path.read_text(encoding="utf-8")
    public_key_pem = public_key_path.read_text(encoding="utf-8")
    if not private_key_pem or not public_key_pem:
        raise ValueError("Shared JWT key files must be non-empty.")
    return JWTKeyMaterial(private_key_pem=private_key_pem, public_key_pem=public_key_pem)


def _atomic_write_text(path: Path, value: str, *, mode: int) -> None:
    """Write one UTF-8 text file atomically with explicit file permissions."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=path.parent,
        prefix=f".{path.name}.",
        delete=False,
    ) as handle:
        handle.write(value)
        handle.flush()
        os.fsync(handle.fileno())
        temp_path = Path(handle.name)

    os.chmod(temp_path, mode)
    os.replace(temp_path, path)


def _maybe_change_file_owner(path: Path, *, uid: int | None, gid: int | None) -> None:
    """Apply file ownership when the runtime platform supports it."""
    if uid is None and gid is None:
        return
    if not hasattr(os, "chown"):
        return
    os.chown(path, -1 if uid is None else uid, -1 if gid is None else gid)


@contextmanager
def _exclusive_file_lock(lock_path: Path) -> Iterator[None]:
    """Acquire a best-effort cross-process lock around key generation."""
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a+b") as handle:
        _lock_file(handle.fileno())
        try:
            yield
        finally:
            _unlock_file(handle.fileno())


def _lock_file(file_descriptor: int) -> None:
    """Acquire an exclusive advisory file lock when the platform supports it."""
    try:
        import fcntl
    except ImportError:
        return
    fcntl.flock(file_descriptor, fcntl.LOCK_EX)


def _unlock_file(file_descriptor: int) -> None:
    """Release an advisory file lock when the platform supports it."""
    try:
        import fcntl
    except ImportError:
        return
    fcntl.flock(file_descriptor, fcntl.LOCK_UN)


if __name__ == "__main__":
    raise SystemExit(main())
