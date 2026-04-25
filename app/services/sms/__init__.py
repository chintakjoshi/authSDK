"""SMS delivery abstraction for SDK-managed MFA.

Release 1 ships only the :class:`LocalSmsSender` development adapter; real
provider integrations (Twilio, SNS) are planned extension points. Application
code should depend exclusively on :class:`app.services.sms.base.SmsSender`
so swapping providers requires no call-site changes.
"""
