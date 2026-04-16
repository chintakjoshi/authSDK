# Admin Dashboard Integration Guide

This document is for engineers building admin dashboards or internal tools
against `authSDK`. The service is headless: it exposes JSON endpoints under
`/admin/*` and emits audit and webhook events. No UI ships in this repo.
Downstream consumers render whatever interface they need on top of this API.

Use this guide alongside:

- `service-api.md` for the full endpoint index and auth model
- `integrate-sdk.md` for general client integration patterns
- the live OpenAPI document (served at `/openapi.json`) for exact schemas

## Auth Model For Dashboards

All `/admin/*` endpoints require one of:

- an admin bearer token (access token issued to a user whose `role == "admin"`)
- a development-only `X-Admin-API-Key` header when the service is configured
  with an admin bootstrap key (do not ship this path to production)

Sensitive mutations additionally require step-up: the dashboard must collect a
short-lived action token (`X-Action-Token` header) from the step-up OTP flow
before calling the mutation. Endpoints that enforce this are noted per
endpoint below.

Dashboards should treat an admin session like any other bearer session:
acquire tokens via the normal `/auth/login` flow, store them the same way,
refresh via `/auth/token`, and log out via `/auth/logout`.

### Step-Up Flow (Action Token)

When an admin mutation returns `step_up_required` or when the dashboard wants
to pre-arm the action, call the action-OTP endpoints on the signed-in admin:

1. `POST /auth/otp/request/action` with `{"action": "revoke_sessions"}`
2. Prompt the admin for the OTP code delivered to their email
3. `POST /auth/otp/verify/action` with the code to receive an action token
4. Pass the action token in `X-Action-Token` on the protected mutation

Action tokens are short-lived (minutes) and single-use per action name.

## Pagination

All list endpoints return a `CursorPageResponse`:

```json
{
  "data": [ /* items */ ],
  "next_cursor": "opaque-string-or-null",
  "has_more": true
}
```

Clients should treat `next_cursor` as opaque and pass it back unchanged. When
`has_more` is false or `next_cursor` is null, the client has reached the end.
Default page size is 50, maximum is 200, minimum is 1.

## Error Shape

Admin errors use the standard service error shape:

```json
{
  "detail": "human readable message",
  "code": "machine_readable_code"
}
```

Common admin codes:

- `invalid_user` (404) — target user not found or soft-deleted
- `invalid_session` (404) — target session not found for this user
- `session_revoked` (409) — session already revoked
- `step_up_required` (401) — missing or expired action token
- `invalid_credentials` / `forbidden` (401/403) — caller is not an admin

## Endpoint Reference

Base path: `/admin`. All examples omit the base URL and bearer header.

### Users

List, read, update role, delete, and erase users.

| Method | Path | Purpose | Step-Up |
|--------|------|---------|---------|
| GET | `/users` | Cursor-paginated user list | No |
| GET | `/users/{user_id}` | User detail (includes `active_session_count`) | No |
| PATCH | `/users/{user_id}` | Change role (admin/user) | Yes |
| DELETE | `/users/{user_id}` | Soft-delete and revoke sessions | Yes |
| DELETE | `/users/{user_id}/erase` | GDPR erasure | Yes |
| PATCH | `/users/{user_id}/otp` | Force-enable or disable email OTP | Yes |

### Sessions

Session inventory, revocation, and bulk revocation. Sessions capture the
client IP address and User-Agent string at login; dashboards can render a
friendly device label using `device_label` (server-derived).

| Method | Path | Purpose | Step-Up |
|--------|------|---------|---------|
| GET | `/users/{user_id}/sessions` | List sessions for a user | No |
| DELETE | `/users/{user_id}/sessions/{session_id}` | Revoke one session | Yes |
| DELETE | `/users/{user_id}/sessions` | Revoke all sessions for a user | Yes |

`GET /users/{user_id}/sessions` query params:

- `status` — `active`, `revoked`, or `all` (default `active`)
- `cursor` — opaque pagination cursor
- `limit` — 1–200 (default 50)

Session list item shape:

```json
{
  "session_id": "uuid",
  "user_id": "uuid",
  "created_at": "2026-04-16T09:00:00Z",
  "last_seen_at": "2026-04-16T10:15:00Z",
  "expires_at": "2026-04-23T09:00:00Z",
  "revoked_at": null,
  "revoke_reason": null,
  "ip_address": "203.0.113.10",
  "user_agent": "Mozilla/5.0 ...",
  "device_label": "Chrome on Windows"
}
```

Notes for dashboard authors:

- `last_seen_at` is advisory. It is refreshed on refresh-token rotation and is
  throttled server-side to once per 60 seconds per session. Do not treat it
  as a real-time presence indicator.
- `device_label` is a best-effort string derived from the raw `user_agent`.
  For unknown agents it may return `Unknown device`. Show both when surface
  space allows; offer the raw UA on hover or in a detail drawer.
- `ip_address` is the client IP observed at login, truncated to 45 chars.
  The service does not resolve it to a country or ISP; if the dashboard needs
  GeoIP, resolve it in the dashboard backend.
- Revoke reasons default to `admin_targeted` (single-session revoke) and
  `admin_revoke_all` (bulk revoke). Callers can override these via the
  optional `reason` body on the DELETE endpoints. Self-service revocations
  default to `self_targeted` and `self_revoke_others`. Treat the field as
  free-form, since integrators may supply arbitrary short slugs.

Both revoke endpoints accept an optional request body specifying a custom
revoke reason. When omitted, the server falls back to `admin_targeted` for
single-session revokes and `admin_revoke_all` for bulk revokes. The reason
is echoed in the response, persisted on the session row, and included in
both the audit event metadata and the `session.revoked` webhook payload.

Request body (optional):

```json
{
  "reason": "compromised_device"
}
```

Constraints: `reason` is free-form, 1–64 characters. Prefer short
machine-readable slugs so dashboards can group by reason; include free-form
human context in the audit metadata layer of your own tooling if needed.

Revoke-one response:

```json
{
  "user_id": "uuid",
  "session_id": "uuid",
  "revoke_reason": "compromised_device"
}
```

Revoke-all response:

```json
{
  "user_id": "uuid",
  "revoked_session_ids": ["uuid", "..."],
  "revoked_session_count": 3,
  "revoke_reason": "compromised_device"
}
```

### User History

A per-user audit feed pre-filtered to login, session, OTP, and password-reset
event types. Use this to render a "recent activity" panel on the user-detail
page without writing audit-log filter queries on the client.

| Method | Path | Purpose | Step-Up |
|--------|------|---------|---------|
| GET | `/users/{user_id}/history` | Paginated user-scoped audit events | No |

Filtered event types (as of this revision):

- `user.login.success`, `user.login.failure`, `user.login.suspicious`
- `user.logout`
- `session.created`, `session.revoked`
- `password.reset.requested`, `password.reset.completed`
- `otp.verified`, `otp.failed`, `otp.expired`, `otp.excessive_failures`
- `otp.admin_toggled`

Items follow `AdminAuditLogItem`. Relevant fields for UI:

- `event_type` — stable machine-readable string (render a friendly label)
- `actor_id` / `actor_type` — who took the action (admin or the user)
- `target_id` — target user id
- `ip_address`, `user_agent` — captured at emission time
- `success`, `failure_reason` — render red/green state for failures
- `metadata` — free-form JSON object, event-specific
- `correlation_id` — stable id for the originating request; useful to stitch
  an event to the server logs

### API Keys

| Method | Path | Purpose | Step-Up |
|--------|------|---------|---------|
| GET | `/api-keys` | List keys | No |
| POST | `/api-keys` | Issue a new key (raw value returned once) | Yes |
| DELETE | `/api-keys/{key_id}` | Revoke a key | Yes |

`POST /api-keys` returns the raw key exactly once in the response body. The
dashboard must surface the value immediately (modal with copy button and a
clear "you will not see this again" warning), then drop it from memory.

### OAuth (M2M) Clients

| Method | Path | Purpose | Step-Up |
|--------|------|---------|---------|
| GET | `/clients` | List M2M clients | No |
| POST | `/clients` | Create client (raw secret returned once) | Yes |
| PATCH | `/clients/{client_id}` | Update name, scopes, TTL, active flag | Yes |
| POST | `/clients/{client_id}/rotate-secret` | Rotate client secret | Yes |
| DELETE | `/clients/{client_id}` | Deactivate client | Yes |

### Webhooks

| Method | Path | Purpose | Step-Up |
|--------|------|---------|---------|
| GET | `/webhooks` | List endpoints | No |
| POST | `/webhooks` | Create endpoint | Yes |
| PATCH | `/webhooks/{endpoint_id}` | Update name/url/events/active | Yes |
| DELETE | `/webhooks/{endpoint_id}` | Delete endpoint | Yes |
| GET | `/webhooks/{endpoint_id}/deliveries` | List deliveries | No |
| POST | `/webhooks/deliveries/{delivery_id}/retry` | Manual retry | Yes |

### Audit Log

| Method | Path | Purpose | Step-Up |
|--------|------|---------|---------|
| GET | `/audit-log` | Unfiltered cursor-paginated audit feed | No |

Prefer `/users/{user_id}/history` for per-user activity panels. Use
`/audit-log` for global views or custom filters; consult the OpenAPI schema
for supported query parameters.

### Signing Keys

| Method | Path | Purpose | Step-Up |
|--------|------|---------|---------|
| POST | `/signing-keys/rotate` | Promote next signing key to active | Yes |

## Building Common Dashboard Views

### User Detail Page

1. `GET /admin/users/{user_id}` — header card (email, role, verified, locked,
   active session count)
2. `GET /admin/users/{user_id}/sessions?status=active` — active sessions table
3. `GET /admin/users/{user_id}/history?limit=20` — recent activity panel
4. Action buttons wire to PATCH role, DELETE sessions, DELETE user, and
   PATCH OTP — each must first obtain an action token via the step-up flow.

### Session Table Columns

Recommended columns:

- Device (`device_label` with tooltip showing raw `user_agent`)
- IP (`ip_address`; render a GeoIP lookup client-side if needed)
- Created (`created_at`)
- Last seen (`last_seen_at`, "never" if null)
- Status (derived from `revoked_at` + `expires_at`)
- Actions (Revoke button — hidden or disabled when already revoked)

### Global Activity Feed

`GET /admin/audit-log` with cursor pagination. Render event type using a
client-side mapping from machine codes to friendly labels, and link each row
to the relevant user detail page when `target_id` is populated.

## Realtime Updates Via Webhooks

The dashboard can subscribe a webhook endpoint to receive session and admin
events as they happen. Relevant event types:

- `session.created`
- `session.revoked`

Webhook payloads contain `user_id`, `reason`, and `session_ids`. Use them to
invalidate client-side caches or push live updates to open dashboards. See
`service-api.md` for the full event catalog and signature verification.

## Things The Service Does Not Do (Yet)

These are explicit non-goals for the current admin surface. Dashboards should
not rely on them and should request them before building around workarounds:

- GeoIP resolution. `ip_address` is stored raw; no country or ASN lookup.
- Device trust / remembered-device management.
- Account lock/unlock controls beyond automatic brute-force lockouts.
- Impersonation / "log in as" for support engineers.

## Versioning And Schema Source Of Truth

The OpenAPI document at `/openapi.json` is the canonical source for request
and response shapes. Breaking changes to admin endpoints are called out in
`operations.md` release notes. Dashboards should regenerate their client
types from OpenAPI on each service release.
