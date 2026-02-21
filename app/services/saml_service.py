"""SAML flow orchestration service."""

from __future__ import annotations

import inspect
from functools import lru_cache

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.saml import SamlCore, SamlProtocolError, get_saml_core
from app.core.sessions import SessionService, get_session_service
from app.models.user import User, UserIdentity
from app.services.token_service import TokenPair, TokenService, get_token_service


class SamlServiceError(Exception):
    """Raised for SAML service flow failures."""

    def __init__(self, detail: str, code: str, status_code: int) -> None:
        super().__init__(detail)
        self.detail = detail
        self.code = code
        self.status_code = status_code


class SamlService:
    """Coordinates SAML protocol flow with user/session issuance."""

    def __init__(
        self,
        saml_core: SamlCore,
        token_service: TokenService,
        session_service: SessionService,
    ) -> None:
        self._saml_core = saml_core
        self._token_service = token_service
        self._session_service = session_service

    def _issue_token_pair(
        self,
        db_session: AsyncSession,
        user_id: str,
        email: str,
        scopes: list[str],
    ):
        """Issue token pair while tolerating legacy test doubles."""
        issue_method = self._token_service.issue_token_pair
        try:
            signature = inspect.signature(issue_method)
        except (TypeError, ValueError):
            signature = None
        if signature and "db_session" in signature.parameters:
            return issue_method(
                db_session=db_session,
                user_id=user_id,
                email=email,
                scopes=scopes,
            )
        return issue_method(user_id=user_id, email=email, scopes=scopes)

    def create_login_url(self, request_data: dict[str, str], relay_state: str | None) -> str:
        """Create SAML login redirect URL."""
        try:
            return self._saml_core.login_url(request_data=request_data, relay_state=relay_state)
        except SamlProtocolError as exc:
            raise SamlServiceError(exc.detail, exc.code, exc.status_code) from exc

    async def complete_callback(
        self,
        db_session: AsyncSession,
        request_data: dict[str, str],
    ) -> TokenPair:
        """Validate SAML assertion, resolve identity, and issue tokens."""
        try:
            assertion = self._saml_core.parse_assertion(request_data=request_data)
        except SamlProtocolError as exc:
            raise SamlServiceError(exc.detail, exc.code, exc.status_code) from exc

        user = await self._upsert_identity_then_resolve_user(
            db_session=db_session,
            provider_user_id=assertion.provider_user_id,
            email=assertion.email,
        )
        issued_pair = self._issue_token_pair(
            db_session=db_session,
            user_id=str(user.id),
            email=user.email,
            scopes=[],
        )
        token_pair = await issued_pair if inspect.isawaitable(issued_pair) else issued_pair
        await self._session_service.create_login_session(
            db_session=db_session,
            user_id=user.id,
            email=user.email,
            scopes=[],
            raw_refresh_token=token_pair.refresh_token,
        )
        return token_pair

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
    ) -> User:
        """Upsert SAML identity first, then resolve/create canonical user."""
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
                user = User(email=email, password_hash=None, is_active=True)
                db_session.add(user)
                await db_session.flush()
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
            user = User(email=email, password_hash=None, is_active=True)
            db_session.add(user)
            await db_session.flush()
            identity.user_id = user.id

        if user.email.lower() != email.lower():
            user.email = email
        if identity.email != email:
            identity.email = email
        await db_session.flush()
        return user

    async def _get_user_by_email(self, db_session: AsyncSession, email: str) -> User | None:
        """Fetch non-deleted user by email."""
        statement = select(User).where(
            func.lower(User.email) == email.lower(),
            User.deleted_at.is_(None),
        )
        result = await db_session.execute(statement)
        return result.scalar_one_or_none()

    async def _get_user_by_id(self, db_session: AsyncSession, user_id: object) -> User | None:
        """Fetch non-deleted user by ID."""
        statement = select(User).where(User.id == user_id, User.deleted_at.is_(None))
        result = await db_session.execute(statement)
        return result.scalar_one_or_none()


@lru_cache
def get_saml_service() -> SamlService:
    """Create and cache SAML service dependency."""
    return SamlService(
        saml_core=get_saml_core(),
        token_service=get_token_service(),
        session_service=get_session_service(),
    )
