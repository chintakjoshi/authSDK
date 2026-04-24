# Security Review

Date: `2026-03-17`
Scope: `app/`, `sdk/`, `loadtests/`, and `tests/`

## Result

- status: `PASS`
- blocking findings: `0`
- follow-up before a production sign-off: execute the documented Locust runs and
  retain the resulting artifacts

## Reviewed Controls

1. OTP codes never appear in logs, API responses, or audit records
   Status: `PASS`

2. `otp_challenge` and `action_token` JWTs are rejected on protected routes
   Status: `PASS`

3. Action tokens carry a specific action claim and fail closed on mismatch
   Status: `PASS`

4. `mfa_enabled` cannot be enabled unless the user is email-verified
   Status: `PASS`

5. OTP challenge isolation prevents user A from using user B's code
   Status: `PASS`

6. OTP Redis keys are deleted immediately after successful verification
   Status: `PASS`

7. OTP failure tracking blocks issuance correctly
   Status: `PASS`

8. SSRF protection covers localhost and private-IP webhook destinations
   Status: `PASS`

9. Audit log remains append-only with no update or delete path
   Status: `PASS`

10. GDPR erasure clears OTP Redis keys and removes durable PII
    Status: `PASS`

11. Last-admin protection cannot be bypassed by concurrent removals
    Status: `PASS`

## Evidence Pointers

- OTP handling: `app/services/otp_service.py`
- webhook SSRF protection: `app/services/webhook_service.py`
- append-only audit behavior: `app/services/audit_service.py`
- erasure flow: `app/services/erasure_service.py`
- admin protection: `app/services/user_service.py`
- SDK JWT enforcement: `sdk/middleware.py`
- representative integration coverage: `tests/integration/`
- representative unit coverage: `tests/unit/`

## Notes

- the webhook volume scenario requires a publicly reachable receiver because
  SSRF protections intentionally block localhost, loopback, and private-network
  destinations
- this review is a code-and-test review, not a substitute for external
  penetration testing or executed performance validation

## Related Docs

- security reporting guidance: `../SECURITY.md`
- load-test procedure: `../loadtests/README.md`
- production runtime guidance: `operations.md`
