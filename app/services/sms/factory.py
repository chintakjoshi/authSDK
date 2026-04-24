"""SMS sender factory with defense-in-depth production guard.

The factory is the single place application code acquires an
:class:`app.services.sms.base.SmsSender`. It enforces two independent
invariants:

1. ``MFA__SMS__PROVIDER=local`` may never materialize an adapter while
   ``APP__ENVIRONMENT=production``. The startup config guard already rejects
   this combination at boot, but a second check here prevents accidental use
   of the local sender if an operator mutates settings at runtime.
2. Real providers (``twilio``, ``sns``) raise :class:`NotImplementedError`
   until their adapters ship; the error message names the requested provider
   so misconfigurations surface loudly.
"""

from __future__ import annotations

from app.config import get_settings, reloadable_singleton
from app.core.sessions import get_redis_client
from app.services.sms.base import SmsSender
from app.services.sms.local import LocalSmsSender

LOCAL_SMS_MAX_MESSAGES_PER_PHONE = 10


@reloadable_singleton
def get_sms_sender() -> SmsSender:
    """Return the configured :class:`SmsSender` or raise on invalid configuration."""
    settings = get_settings()
    provider = settings.mfa.sms.provider

    if provider == "local":
        if settings.app.environment == "production":
            raise RuntimeError(
                "LocalSmsSender is not permitted in production; "
                "configure MFA__SMS__PROVIDER to a real provider."
            )
        return LocalSmsSender(
            redis_client=get_redis_client(),
            ttl_seconds=settings.mfa.sms.local_ttl_seconds,
            max_messages_per_phone=LOCAL_SMS_MAX_MESSAGES_PER_PHONE,
        )

    raise NotImplementedError(
        f"SMS provider '{provider}' is not implemented in this release; "
        "only the 'local' development adapter is available in v1."
    )
