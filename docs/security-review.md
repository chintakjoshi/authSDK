# Security Review Checklist

Date: 2026-03-17  
Scope: auth-service additions across `app/`, `sdk/`, `loadtests/`, and `tests/`

## Result

- Status: `PASS`
- Blocking findings: `0`
- Follow-up needed before a production sign-off: execute the Locust runs in [loadtests/README.md](/c:/Users/chint/Desktop/authSDK/loadtests/README.md) and retain the output artifacts

## Checklist

1. OTP codes never appear in logs, API responses, or audit records
- Status: `PASS`
- Evidence:
  - OTP email bodies are constructed only in [otp_service.py](/c:/Users/chint/Desktop/authSDK/app/services/otp_service.py)
  - Logging redaction remains centralized in [logging.py](/c:/Users/chint/Desktop/authSDK/app/middleware/logging.py)
  - OTP API responses expose challenge tokens or action tokens, never raw codes, in [otp.py](/c:/Users/chint/Desktop/authSDK/app/routers/otp.py)
  - OTP audit assertions live in [test_email_otp_real.py](/c:/Users/chint/Desktop/authSDK/tests/integration/test_email_otp_real.py)

2. `otp_challenge` and `action_token` JWTs are rejected on protected routes
- Status: `PASS`
- Evidence:
  - JWT type validation rejects these token types in [jwt.py](/c:/Users/chint/Desktop/authSDK/app/core/jwt.py)
  - SDK middleware rejection coverage is in [test_sdk_middleware.py](/c:/Users/chint/Desktop/authSDK/tests/unit/test_sdk_middleware.py)

3. Action tokens carry a specific action claim and fail closed on claim mismatch
- Status: `PASS`
- Evidence:
  - Action token issuance includes the `action` claim in [otp_service.py](/c:/Users/chint/Desktop/authSDK/app/services/otp_service.py)
  - Validation and mismatch checks are in [otp_service.py](/c:/Users/chint/Desktop/authSDK/app/services/otp_service.py)
  - Coverage exists in [test_otp_service_additional.py](/c:/Users/chint/Desktop/authSDK/tests/unit/test_otp_service_additional.py)

4. `email_otp_enabled` cannot be enabled unless the user is email-verified
- Status: `PASS`
- Evidence:
  - Enforcement is in [otp_service.py](/c:/Users/chint/Desktop/authSDK/app/services/otp_service.py)
  - Integration coverage exists in [test_email_otp_real.py](/c:/Users/chint/Desktop/authSDK/tests/integration/test_email_otp_real.py)

5. OTP challenge isolation prevents user A's challenge from accepting user B's code
- Status: `PASS`
- Evidence:
  - Challenge tokens carry the target subject and are verified against user-specific Redis state in [otp_service.py](/c:/Users/chint/Desktop/authSDK/app/services/otp_service.py)
  - Load-test runtime validation is implemented in [locustfile.py](/c:/Users/chint/Desktop/authSDK/loadtests/locustfile.py)

6. OTP Redis keys are deleted immediately after successful verification
- Status: `PASS`
- Evidence:
  - Login and action OTP cleanup is handled in [otp_service.py](/c:/Users/chint/Desktop/authSDK/app/services/otp_service.py)
  - Replay-protection coverage exists in [test_otp_service_flow_additional.py](/c:/Users/chint/Desktop/authSDK/tests/unit/test_otp_service_flow_additional.py)

7. OTP failure tracking blocks issuance correctly
- Status: `PASS`
- Evidence:
  - Shared OTP failure counters and issuance-block logic are in [otp_service.py](/c:/Users/chint/Desktop/authSDK/app/services/otp_service.py)
  - Integration coverage exists in [test_email_otp_real.py](/c:/Users/chint/Desktop/authSDK/tests/integration/test_email_otp_real.py)

8. SSRF protection covers localhost and private-IP webhook destinations
- Status: `PASS`
- Evidence:
  - URL parsing, hostname resolution, and private-IP rejection are in [webhook_service.py](/c:/Users/chint/Desktop/authSDK/app/services/webhook_service.py)
  - Integration coverage exists in [test_webhook_system_real.py](/c:/Users/chint/Desktop/authSDK/tests/integration/test_webhook_system_real.py)
  - Additional helper coverage exists in [test_webhook_service_additional.py](/c:/Users/chint/Desktop/authSDK/tests/unit/test_webhook_service_additional.py)

9. Audit log remains append-only with no UPDATE or DELETE path
- Status: `PASS`
- Evidence:
  - Audit writes are create-only in [audit_service.py](/c:/Users/chint/Desktop/authSDK/app/services/audit_service.py)
  - No production code path updates or deletes audit rows

10. GDPR erasure clears OTP Redis keys and removes PII from durable auth records
- Status: `PASS`
- Evidence:
  - Erasure orchestration is in [erasure_service.py](/c:/Users/chint/Desktop/authSDK/app/services/erasure_service.py)
  - OTP cleanup helper is in [otp_service.py](/c:/Users/chint/Desktop/authSDK/app/services/otp_service.py)
  - Integration coverage exists in [test_gdpr_erasure_real.py](/c:/Users/chint/Desktop/authSDK/tests/integration/test_gdpr_erasure_real.py)

11. Last-admin protection cannot be bypassed by concurrent removals
- Status: `PASS`
- Evidence:
  - Row-lock enforcement lives in [user_service.py](/c:/Users/chint/Desktop/authSDK/app/services/user_service.py)
  - Admin router coverage for protection exists in [test_admin_router_real.py](/c:/Users/chint/Desktop/authSDK/tests/integration/test_admin_router_real.py)
  - Service-level protection coverage exists in [test_user_roles_real.py](/c:/Users/chint/Desktop/authSDK/tests/integration/test_user_roles_real.py)

## Notes

- The webhook-volume load scenario intentionally requires a public receiver because SSRF protections reject `localhost`, loopback, and private-network webhook URLs.
- This review is a code-and-test review. It complements, but does not replace, executed load runs and external penetration testing.
