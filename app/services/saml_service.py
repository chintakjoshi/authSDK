"""SAML flow orchestration service."""

from __future__ import annotations

import hmac
import inspect
import json
import secrets
from dataclasses import dataclass

from redis.asyncio.client import Redis
from redis.exceptions import RedisError
from sqlalchemy import func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings, reloadable_singleton
from app.core.callable_compat import add_supported_kwarg, get_callable_parameter_names
from app.core.saml import SamlCore, SamlProtocolError, get_saml_core
from app.core.sessions import SessionService, get_redis_client, get_session_service
from app.models.user import User, UserIdentity
from app.services.token_service import TokenPair, TokenService, get_token_service


class SamlServiceError(Exception):
    """Raised for SAML service flow failures."""

    def __init__(self, detail: str, code: str, status_code: int) -> None:
        super().__init__(detail)
        self.detail = detail
        self.code = code
        self.status_code = status_code


@dataclass(frozen=True)
class SamlStateRecord:
    """Serialized SAML request state stored in Redis."""

    request_id: str
    redirect_uri: str | None = None
    relay_state: str | None = None
    audience: str | None = None


@dataclass(frozen=True)
class SamlCallbackCompletion:
    """Completed SAML login result including optional caller context."""

    token_pair: TokenPair
    redirect_uri: str | None = None
    relay_state: str | None = None

    @property
    def access_token(self) -> str:
        """Expose access token for compatibility with token-pair call sites."""
        return self.token_pair.access_token

    @property
    def refresh_token(self) -> str:
        """Expose refresh token for compatibility with token-pair call sites."""
        return self.token_pair.refresh_token


class SamlService:
    """Coordinates SAML protocol flow with user/session issuance."""

    _ATOMIC_GET_AND_DELETE_SCRIPT = """
local value = redis.call("GET", KEYS[1])
if value then
    redis.call("DEL", KEYS[1])
end
return value
"""

    def __init__(
        self,
        saml_core: SamlCore,
        token_service: TokenService,
        session_service: SessionService,
        redis_client: Redis,
        allowed_redirect_uris: tuple[str, ...] = (),
    ) -> None:
        self._saml_core = saml_core
        self._token_service = token_service
        self._session_service = session_service
        self._redis = redis_client
        self._allowed_redirect_uris = allowed_redirect_uris
        self._state_ttl_seconds = 600

    def _issue_token_pair(
        self,
        db_session: AsyncSession,
        user_id: str,
        email: str,
        role: str,
        email_verified: bool,
        email_otp_enabled: bool,
        scopes: list[str],
        audience: str | None = None,
    ):
        """Issue token pair while tolerating legacy test doubles."""
        issue_method = self._token_service.issue_token_pair
        supported_parameters = get_callable_parameter_names(issue_method)
        kwargs: dict[str, object] = {"user_id": user_id, "email": email, "scopes": scopes}
        if supported_parameters is not None and "db_session" in supported_parameters:
            kwargs["db_session"] = db_session
        add_supported_kwarg(
            kwargs,
            supported_parameters=supported_parameters,
            name="role",
            value=role,
        )
        add_supported_kwarg(
            kwargs,
            supported_parameters=supported_parameters,
            name="email_verified",
            value=email_verified,
        )
        add_supported_kwarg(
            kwargs,
            supported_parameters=supported_parameters,
            name="email_otp_enabled",
            value=email_otp_enabled,
        )
        add_supported_kwarg(
            kwargs,
            supported_parameters=supported_parameters,
            name="audience",
            value=audience,
        )
        add_supported_kwarg(
            kwargs,
            supported_parameters=supported_parameters,
            name="audiences",
            value=audience,
        )
        return issue_method(**kwargs)

    async def create_login_url(
        self,
        request_data: dict[str, str],
        relay_state: str | None,
        audience: str | None = None,
    ) -> str:
        """Create SAML login redirect URL."""
        normalized_relay_state = self._normalize_optional_string(relay_state)
        redirect_uri = self._resolve_post_auth_redirect_uri(normalized_relay_state)
        try:
            state_token = self._generate_state_token()
            login_request = self._saml_core.login_url(
                request_data=request_data,
                relay_state=state_token,
            )
        except SamlProtocolError as exc:
            raise SamlServiceError(exc.detail, exc.code, exc.status_code) from exc
        await self._store_state(
            state=state_token,
            record=SamlStateRecord(
                request_id=login_request.request_id,
                redirect_uri=redirect_uri,
                relay_state=None if redirect_uri is not None else normalized_relay_state,
                audience=self._normalize_optional_string(audience),
            ),
        )
        return login_request.redirect_url

    async def complete_callback(
        self,
        db_session: AsyncSession,
        request_data: dict[str, str],
    ) -> SamlCallbackCompletion:
        """Validate SAML assertion, resolve identity, and issue tokens."""
        relay_state = self._extract_relay_state(request_data)
        state_record = await self._consume_state(relay_state)
        try:
            assertion = self._saml_core.parse_assertion(
                request_data=request_data,
                expected_request_id=state_record.request_id,
            )
        except SamlProtocolError as exc:
            raise SamlServiceError(exc.detail, exc.code, exc.status_code) from exc

        user = await self._upsert_identity_then_resolve_user(
            db_session=db_session,
            provider_user_id=assertion.provider_user_id,
            email=assertion.email,
            email_verified=assertion.email_verified,
        )
        issued_pair = self._issue_token_pair(
            db_session=db_session,
            user_id=str(user.id),
            email=user.email,
            role=user.role,
            email_verified=user.email_verified,
            email_otp_enabled=user.email_otp_enabled,
            scopes=[],
            audience=state_record.audience,
        )
        token_pair = await issued_pair if inspect.isawaitable(issued_pair) else issued_pair
        await self._session_service.create_login_session(
            db_session=db_session,
            user_id=user.id,
            email=user.email,
            role=user.role,
            email_verified=user.email_verified,
            email_otp_enabled=user.email_otp_enabled,
            scopes=[],
            raw_access_token=token_pair.access_token,
            raw_refresh_token=token_pair.refresh_token,
        )
        return SamlCallbackCompletion(
            token_pair=token_pair,
            redirect_uri=state_record.redirect_uri,
            relay_state=state_record.relay_state,
        )

    def metadata_xml(self) -> str:
        """Return current SP metadata XML."""
        try:
            return self._saml_core.metadata_xml()
        except SamlProtocolError as exc:
            raise SamlServiceError(exc.detail, exc.code, exc.status_code) from exc

    async def _upsert_identity_then_resolve_user(
        self,
        db_session: AsyncSession,
        provider_user_id: str,
        email: str,
        email_verified: bool,
    ) -> User:
        """Upsert SAML identity first, then resolve/create canonical user."""
        try:
            identity_stmt = select(UserIdentity).where(
                UserIdentity.provider == "saml",
                UserIdentity.provider_user_id == provider_user_id,
                UserIdentity.deleted_at.is_(None),
            )
            identity_result = await db_session.execute(identity_stmt)
            identity = identity_result.scalar_one_or_none()

            if identity is None:
                user = await self._get_user_by_email(db_session=db_session, email=email)
                if user is None:
                    await self._ensure_email_available_for_new_user(
                        db_session=db_session,
                        email=email,
                    )
                    user = await self._create_user(
                        db_session=db_session,
                        email=email,
                        email_verified=email_verified,
                    )
                elif not email_verified:
                    raise self._blocked_login_error()
                identity = UserIdentity(
                    user_id=user.id,
                    provider="saml",
                    provider_user_id=provider_user_id,
                    email=email,
                )
                db_session.add(identity)
                await db_session.flush()
                return user

            user = await self._get_user_by_id(db_session=db_session, user_id=identity.user_id)
            if user is None:
                deleted_or_inactive_user = await self._get_deleted_or_inactive_user_by_id(
                    db_session=db_session,
                    user_id=identity.user_id,
                )
                if deleted_or_inactive_user is not None:
                    raise self._blocked_login_error()
                await self._ensure_email_available_for_new_user(
                    db_session=db_session,
                    email=email,
                )
                user = await self._create_user(
                    db_session=db_session,
                    email=email,
                    email_verified=email_verified,
                )
                identity.user_id = user.id

            if user.email.lower() != email.lower():
                await self._ensure_email_available_for_existing_user(
                    db_session=db_session,
                    user=user,
                    email=email,
                )
                user.email = email
            if email_verified and not user.email_verified:
                user.email_verified = True
            if identity.email != email:
                identity.email = email
            await db_session.flush()
            return user
        except IntegrityError as exc:
            await db_session.rollback()
            raise self._blocked_login_error() from exc

    async def _get_user_by_email(self, db_session: AsyncSession, email: str) -> User | None:
        """Fetch active, non-deleted user by email."""
        statement = select(User).where(
            func.lower(User.email) == email.lower(),
            User.deleted_at.is_(None),
            User.is_active.is_(True),
        )
        result = await db_session.execute(statement)
        return result.scalar_one_or_none()

    async def _get_user_by_id(self, db_session: AsyncSession, user_id: object) -> User | None:
        """Fetch active, non-deleted user by ID."""
        statement = select(User).where(
            User.id == user_id,
            User.deleted_at.is_(None),
            User.is_active.is_(True),
        )
        result = await db_session.execute(statement)
        return result.scalar_one_or_none()

    async def _get_deleted_or_inactive_user_by_email(
        self,
        db_session: AsyncSession,
        email: str,
    ) -> User | None:
        """Fetch a deleted or inactive user row when the email is reserved."""
        statement = select(User).where(
            func.lower(User.email) == email.lower(),
            or_(User.deleted_at.is_not(None), User.is_active.is_(False)),
        )
        result = await db_session.execute(statement)
        return result.scalar_one_or_none()

    async def _get_deleted_or_inactive_user_by_id(
        self,
        db_session: AsyncSession,
        user_id: object,
    ) -> User | None:
        """Fetch a deleted or inactive user row by ID when login should stay blocked."""
        statement = select(User).where(
            User.id == user_id,
            or_(User.deleted_at.is_not(None), User.is_active.is_(False)),
        )
        result = await db_session.execute(statement)
        return result.scalar_one_or_none()

    async def _ensure_email_available_for_new_user(
        self,
        db_session: AsyncSession,
        *,
        email: str,
    ) -> None:
        """Raise when the SAML email belongs to a deleted or inactive account."""
        deleted_or_inactive_user = await self._get_deleted_or_inactive_user_by_email(
            db_session=db_session,
            email=email,
        )
        if deleted_or_inactive_user is not None:
            raise self._blocked_login_error()

    async def _ensure_email_available_for_existing_user(
        self,
        db_session: AsyncSession,
        *,
        user: User,
        email: str,
    ) -> None:
        """Raise when an email update would collide with another reserved account."""
        active_user = await self._get_user_by_email(db_session=db_session, email=email)
        if active_user is not None and active_user.id != user.id:
            raise self._blocked_login_error()
        deleted_or_inactive_user = await self._get_deleted_or_inactive_user_by_email(
            db_session=db_session,
            email=email,
        )
        if deleted_or_inactive_user is not None and deleted_or_inactive_user.id != user.id:
            raise self._blocked_login_error()

    async def _create_user(
        self,
        db_session: AsyncSession,
        *,
        email: str,
        email_verified: bool,
    ) -> User:
        """Create a new canonical user for a first-time SAML login."""
        user = User(
            email=email,
            password_hash=None,
            is_active=True,
            role="user",
            email_verified=email_verified,
        )
        db_session.add(user)
        await db_session.flush()
        return user

    @staticmethod
    def _blocked_login_error() -> SamlServiceError:
        """Return the stable auth failure for deleted or conflicting SAML accounts."""
        return SamlServiceError("Invalid credentials.", "invalid_credentials", 401)

    async def _store_state(self, *, state: str, record: SamlStateRecord) -> None:
        """Persist SAML request state in Redis for callback validation."""
        try:
            await self._redis.setex(
                self._state_key(state),
                self._state_ttl_seconds,
                json.dumps(
                    {
                        "request_id": record.request_id,
                        "redirect_uri": record.redirect_uri,
                        "relay_state": record.relay_state,
                        "audience": record.audience,
                    }
                ),
            )
        except RedisError as exc:
            raise SamlServiceError(
                "SAML assertion invalid.",
                "saml_assertion_invalid",
                503,
            ) from exc

    async def _consume_state(self, state: str) -> SamlStateRecord:
        """Load and delete the one-time SAML request state."""
        key = self._state_key(state)
        try:
            if hasattr(self._redis, "getdel"):
                raw_payload = await self._redis.getdel(key)
            else:
                raw_payload = await self._redis.eval(self._ATOMIC_GET_AND_DELETE_SCRIPT, 1, key)
        except RedisError as exc:
            raise SamlServiceError(
                "SAML assertion invalid.",
                "saml_assertion_invalid",
                503,
            ) from exc

        if raw_payload is None:
            raise SamlServiceError("SAML assertion invalid.", "saml_assertion_invalid", 401)
        try:
            payload_dict = json.loads(raw_payload)
            return SamlStateRecord(**payload_dict)
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise SamlServiceError(
                "SAML assertion invalid.", "saml_assertion_invalid", 401
            ) from exc

    @staticmethod
    def _generate_state_token() -> str:
        """Generate opaque RelayState token for request correlation."""
        return secrets.token_urlsafe(32)

    @staticmethod
    def _extract_relay_state(request_data: dict[str, object]) -> str:
        """Extract RelayState from GET or POST request payloads."""
        for key in ("post_data", "get_data"):
            payload = request_data.get(key, {})
            if not isinstance(payload, dict):
                continue
            relay_state = str(payload.get("RelayState", "")).strip()
            if relay_state:
                return relay_state
        raise SamlServiceError("SAML assertion invalid.", "saml_assertion_invalid", 401)

    @staticmethod
    def _state_key(state: str) -> str:
        """Build Redis key for one-time SAML request state."""
        return f"saml_state:{state}"

    def _resolve_post_auth_redirect_uri(self, redirect_uri: str | None) -> str | None:
        """Validate an optional post-auth redirect target against the allowlist."""
        if redirect_uri is None:
            return None
        for allowed in self._allowed_redirect_uris:
            if hmac.compare_digest(redirect_uri, allowed):
                return redirect_uri
        return None

    @staticmethod
    def _normalize_optional_string(value: str | None) -> str | None:
        """Normalize optional string inputs and treat blanks as missing."""
        if value is None:
            return None
        normalized = value.strip()
        return normalized or None


@reloadable_singleton
def get_saml_service() -> SamlService:
    """Create and cache SAML service dependency."""
    settings = get_settings()
    return SamlService(
        saml_core=get_saml_core(),
        token_service=get_token_service(),
        session_service=get_session_service(),
        redis_client=get_redis_client(),
        allowed_redirect_uris=tuple(str(uri) for uri in settings.oauth.redirect_uri_allowlist),
    )
