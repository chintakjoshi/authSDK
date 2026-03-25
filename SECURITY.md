# Security

Security-sensitive behavior in this repository includes token issuance and
validation, session revocation, OTP flows, API-key introspection, webhook
delivery safeguards, admin step-up flows, and signing-key rotation.

## Reporting A Vulnerability

Please do not open a public issue for suspected security vulnerabilities.
Share details privately with the maintainers through your normal security
reporting channel.

Include:

- affected area or endpoint
- impact and exploit conditions
- reproduction steps or proof of concept
- logs, traces, or example payloads when safe to share

## Security Documentation

- reviewed controls and evidence: `docs/security-review.md`
- production runtime guidance: `docs/operations.md`
- configuration guardrails: `docs/configuration.md`

## Current Security Posture Notes

- production startup rejects several unsafe configurations
- webhook destinations include SSRF protections
- admin-sensitive actions enforce step-up checks
- JWT signing keys support rotation with overlap windows
- OTP codes are intentionally kept out of logs and API responses
