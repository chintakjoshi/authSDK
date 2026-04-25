"""Core MFA primitives: phone helpers, code helpers, Redis challenge store.

These modules expose pure, provider-agnostic building blocks consumed by the
higher-level :mod:`app.services.mfa_service` orchestrator. Nothing in this
package performs HTTP I/O or issues tokens directly; it is safe to depend on
from any layer that already uses :mod:`app.core.otp`.
"""
