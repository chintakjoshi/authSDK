# Self-Service Sessions And Activity Guide

This document is for engineers building end-user account UIs — "Security"
or "Active devices" panels — on top of `authSDK`. Unlike the admin
endpoints, these routes are bearer-authenticated as the end user and scope
all reads and writes to that user automatically.

Use alongside:

- `service-api.md` for the endpoint index and auth model
- `admin-dashboard-integration.md` for the admin equivalents
- the live OpenAPI document at `/openapi.json`

## Endpoint Summary

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/auth/sessions` | List the caller's sessions |
| DELETE | `/auth/sessions` | Revoke all the caller's other sessions |
| DELETE | `/auth/sessions/{session_id}` | Revoke one of the caller's sessions |
| GET | `/auth/history` | List the caller's recent security activity |

All four require a valid bearer access token in the `Authorization` header.
No step-up / action token is required — self-service actions are scoped to
the caller's own account. Browser apps should call these through their
existing auth proxy the same way they call other `/auth/*` routes.

## List Sessions

`GET /auth/sessions`

Query params:

- `status` — `active`, `revoked`, or `all` (default `active`)
- `cursor` — opaque pagination cursor
- `limit` — 1–200 (default 50)

Response shape (one item):

```json
{
  "session_id": "uuid",
  "created_at": "2026-04-16T09:00:00Z",
  "last_seen_at": "2026-04-16T10:15:00Z",
  "expires_at": "2026-04-23T09:00:00Z",
  "revoked_at": null,
  "revoke_reason": null,
  "ip_address": "203.0.113.10",
  "user_agent": "Mozilla/5.0 ...",
  "device_label": "Chrome on Windows",
  "is_current": true
}
```

UI guidance:

- Render `device_label` prominently, with the raw `user_agent` on hover.
- Badge `is_current: true` as "This device" so users know which row would
  log them out if they try to revoke it.
- `last_seen_at` is throttled server-side (updated at most once per 60s on
  token refresh). Present it as approximate ("Last seen ~10 minutes ago"),
  not a precise heartbeat.
- `ip_address` is the raw IP seen at login/refresh. If you need city or
  country, resolve it in your own backend — the service does not.

## Revoke One Session

`DELETE /auth/sessions/{session_id}`

Revokes a single session owned by the caller. The caller's current session
is protected: the endpoint returns `400 cannot_revoke_current_session` if
the supplied `session_id` matches the session backing the current access
token. Users should call `POST /auth/logout` to end the current session.

Request body (optional):

```json
{ "reason": "stolen_laptop" }
```

`reason` is 1–64 characters. When omitted the service uses `self_targeted`.

Response:

```json
{
  "session_id": "uuid",
  "revoke_reason": "stolen_laptop"
}
```

## Revoke All Other Sessions

`DELETE /auth/sessions`

Revokes every active session owned by the caller except the current one.
Useful for a "Sign out everywhere else" button after a password change or
suspicious-activity alert.

Request body (optional):

```json
{ "reason": "password_changed" }
```

When omitted the service uses `self_revoke_others`.

Response:

```json
{
  "revoked_session_ids": ["uuid", "..."],
  "revoked_session_count": 3,
  "revoke_reason": "password_changed"
}
```

If there are no other sessions, `revoked_session_count` is 0 and
`revoked_session_ids` is empty.

## Activity History

`GET /auth/history`

Paginated feed of the caller's security-relevant events. The server
pre-filters to login, session, password-reset, and OTP event types so
clients don't need to encode that list.

Query params:

- `cursor` — opaque pagination cursor
- `limit` — 1–200 (default 50)

Item shape:

```json
{
  "id": "uuid",
  "event_type": "user.login.success",
  "created_at": "2026-04-16T10:15:00Z",
  "ip_address": "203.0.113.10",
  "user_agent": "Mozilla/5.0 ...",
  "success": true,
  "failure_reason": null,
  "metadata": { "provider": "password" }
}
```

Event types you will see:

- `user.login.success`, `user.login.failure`, `user.login.suspicious`
- `user.logout`
- `session.created`, `session.revoked`
- `password.reset.requested`, `password.reset.completed`
- `otp.verified`, `otp.failed`, `otp.expired`, `otp.excessive_failures`
- `otp.admin_toggled`

UI guidance:

- Keep a client-side map from `event_type` to a friendly label. Render
  failures in a warning style using `success` + `failure_reason`.
- `metadata` is free-form JSON and may include `provider`, `session_id`,
  `reason`, etc. Do not rely on any specific key being present.
- Correlate with the session list by comparing `metadata.session_id` or
  `metadata.session_ids` to the `session_id` field on sessions when
  surfacing "this login created session X" context.

## Pagination

All list endpoints return the same cursor page shape as admin lists:

```json
{
  "data": [],
  "next_cursor": "opaque-string-or-null",
  "has_more": true
}
```

Pass `next_cursor` back unchanged. Stop when it's null or `has_more` is
false.

## Error Codes

- `invalid_token` (401) — missing, malformed, or expired bearer
- `cannot_revoke_current_session` (400) — tried to revoke the current
  session via DELETE-one; use logout instead
- `invalid_session` (404) — session id not owned by caller or not found
- `session_revoked` (409) — session is already revoked
- `invalid_status` (400) — `status` query parameter is not one of the
  allowed values

## Common UI Flows

### Security Page

1. `GET /auth/sessions?status=active` — render active devices table.
2. Row action: `DELETE /auth/sessions/{id}` — refresh the list on success.
3. "Sign out everywhere else" button: `DELETE /auth/sessions` — show a
   confirmation and refresh the list.
4. `GET /auth/history?limit=20` — render a recent-activity panel under
   the sessions table.

### Post-Password-Change Prompt

After a successful password change flow, prompt the user:

> "Sign out of other devices for security?"

On confirm, call `DELETE /auth/sessions` with
`{"reason": "password_changed"}`. Your app can then poll or refresh the
sessions list to show the cleanup took effect.
