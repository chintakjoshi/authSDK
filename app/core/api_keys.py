"""API key generation, hashing, and comparison primitives."""

from __future__ import annotations

import hmac
import secrets
from hashlib import sha256


class APIKeyCore:
    """Core API key operations."""

    _PREFIX = "sk_"

    def generate_raw_key(self) -> str:
        """Generate an API key with required `sk_` prefix format."""
        return f"{self._PREFIX}{secrets.token_urlsafe(32)}"

    def hash_key(self, raw_key: str) -> str:
        """Hash raw API key using SHA-256 hex digest."""
        return sha256(raw_key.encode("utf-8")).hexdigest()

    def key_prefix(self, raw_key: str) -> str:
        """Return display prefix from the first 8 characters of raw key."""
        return raw_key[:8]

    def is_valid_format(self, raw_key: str) -> bool:
        """Validate API key prefix format."""
        if len(raw_key) < len(self._PREFIX):
            return False
        return hmac.compare_digest(raw_key[: len(self._PREFIX)], self._PREFIX)

    def hash_matches(self, expected_hash: str, raw_key: str) -> bool:
        """Constant-time compare between stored hash and raw key hash."""
        candidate_hash = self.hash_key(raw_key)
        return hmac.compare_digest(expected_hash, candidate_hash)

    def scopes_from_storage(self, scope_field: str) -> list[str]:
        """Convert stored scope string to response scope array."""
        return [scope.strip() for scope in scope_field.split(",") if scope.strip()]
