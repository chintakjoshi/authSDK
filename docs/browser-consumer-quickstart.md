# Browser Consumer Quickstart

This guide is for browser applications that want to adopt `authSDK` browser
sessions without storing access or refresh tokens in JavaScript-managed
storage.

Use this guide when:

- your frontend runs in a browser
- you control the app origin and can proxy auth and app API traffic through it
- you want `HttpOnly` cookie sessions plus SDK-backed JWT validation in the
  downstream API

If you are integrating a CLI, mobile app, server-to-server client, or another
non-browser consumer, keep using the token-mode contracts in
`service-api.md`.

## Recommended Topology

The preferred browser deployment model is one app origin with two same-origin
proxy paths:

```text
Browser
  |
  +--> https://app.example.com/_auth/*   -> reverse proxy -> authSDK
  |
  +--> https://app.example.com/api/*     -> reverse proxy -> downstream app
```

Examples in this guide assume:

- the browser calls `/_auth/*` for auth flows
- your reverse proxy rewrites `/_auth/login` to `POST /auth/login`,
  `/_auth/token` to `POST /auth/token`, `/_auth/logout` to `POST /auth/logout`,
  and `/_auth/csrf` to `GET /auth/csrf`
- your reverse proxy also exposes `/_auth/.well-known/jwks.json` for the
  downstream API if it resolves JWKS through the same origin

Why this topology is recommended:

- cookies stay host-only to one application origin
- browser requests can use `credentials: "include"` cleanly
- you avoid broad CORS and cross-subdomain cookie behavior
- every browser app can adopt the same pattern without app-specific auth logic

## Service-Side Setup

Enable browser sessions in `authSDK`:

```text
BROWSER_SESSIONS__ENABLED=true
```

Recommended local HTTP baseline for same-origin browser apps:

```text
BROWSER_SESSIONS__ACCESS_COOKIE_NAME=auth_access
BROWSER_SESSIONS__REFRESH_COOKIE_NAME=auth_refresh
BROWSER_SESSIONS__CSRF_COOKIE_NAME=auth_csrf
BROWSER_SESSIONS__SAME_SITE=lax
BROWSER_SESSIONS__SECURE_ONLY=false
BROWSER_SESSIONS__ACCESS_COOKIE_PATH=/
BROWSER_SESSIONS__REFRESH_COOKIE_PATH=/_auth
BROWSER_SESSIONS__CSRF_COOKIE_PATH=/
BROWSER_SESSIONS__CSRF_HEADER_NAME=X-CSRF-Token
```

Production guidance:

- local HTTP development should use non-prefixed cookie names such as
  `auth_access`, `auth_refresh`, and `auth_csrf`
- set `BROWSER_SESSIONS__SECURE_ONLY=true`
- leave `BROWSER_SESSIONS__COOKIE_DOMAIN` unset for host-only cookies
- use HTTPS for the frontend origin and all proxied auth routes
- for HTTPS host-only cookies, a good baseline is:

```text
BROWSER_SESSIONS__ACCESS_COOKIE_NAME=__Host-auth_access
BROWSER_SESSIONS__REFRESH_COOKIE_NAME=__Secure-auth_refresh
BROWSER_SESSIONS__CSRF_COOKIE_NAME=__Host-auth_csrf
BROWSER_SESSIONS__ACCESS_COOKIE_PATH=/
BROWSER_SESSIONS__REFRESH_COOKIE_PATH=/_auth
BROWSER_SESSIONS__CSRF_COOKIE_PATH=/
```

Prefix rules matter:

- `__Host-*` cookies require `Secure`, no `Domain`, and `Path=/`
- that means `__Host-auth_refresh` cannot be used with
  `BROWSER_SESSIONS__REFRESH_COOKIE_PATH=/_auth`
- `authSDK` now rejects invalid prefix and path combinations at startup

Transport note:

- browser-session requests no longer need to send
  `X-Auth-Session-Transport: cookie` once CSRF/session cookies establish
  browser-session context
- the header is still accepted and remains useful for explicitness or mixed
  clients
- `X-Auth-Session-Transport: token` still forces legacy token-pair behavior

## Downstream API Setup

Your downstream Python service should adopt the SDK middleware with cookie
support enabled:

```python
from fastapi import FastAPI
from sdk import CookieCSRFMiddleware, JWTAuthMiddleware

app = FastAPI()

app.add_middleware(
    CookieCSRFMiddleware,
    csrf_cookie_name="auth_csrf",
    csrf_header_name="X-CSRF-Token",
    access_cookie_name="auth_access",
)
app.add_middleware(
    JWTAuthMiddleware,
    auth_base_url="https://app.example.com/_auth",
    expected_audience="jobs-api",
    token_sources=["authorization", "cookie"],
    access_cookie_name="auth_access",
)
```

Important notes:

- register `CookieCSRFMiddleware` before `JWTAuthMiddleware`; FastAPI/Starlette
  runs the most recently added middleware first
- the cookie names in this example match the local HTTP baseline above; in
  HTTPS production, match your configured names such as `__Host-auth_access`
  and `__Host-auth_csrf`
- keep `token_sources=["authorization", "cookie"]` unless you are certain your
  service will never receive bearer tokens from non-browser clients
- `Authorization` still wins if both a bearer token and cookie are present
- `CookieCSRFMiddleware` protects unsafe requests only when the request was
  authenticated from a cookie

## Browser Flow

### 1. Bootstrap CSRF

Before login, fetch a CSRF token from the same-origin auth proxy:

```ts
const csrfResponse = await fetch("/_auth/csrf", {
  credentials: "include",
});

if (!csrfResponse.ok) {
  throw new Error("Unable to bootstrap CSRF.");
}
```

This request sets the non-`HttpOnly` CSRF cookie and returns the same token in
the response body.

### 2. Login With Cookie Transport

```ts
const csrfToken = readCookie("auth_csrf");

const loginResponse = await fetch("/_auth/login", {
  method: "POST",
  credentials: "include",
  headers: {
    "Content-Type": "application/json",
    "X-CSRF-Token": csrfToken,
  },
  body: JSON.stringify({
    email: "user@example.com",
    password: "Password123!",
    audience: "jobs-api",
  }),
});
```

Cookie-mode login returns a minimal response body and sets the access and
refresh cookies on the browser session.

### 3. Call The App API

Safe requests:

```ts
await fetch("/api/v1/jobs", {
  credentials: "include",
});
```

Unsafe requests:

```ts
const csrfToken = readCookie("auth_csrf");

await fetch("/api/v1/profile", {
  method: "PATCH",
  credentials: "include",
  headers: {
    "Content-Type": "application/json",
    "X-CSRF-Token": csrfToken,
  },
  body: JSON.stringify({ display_name: "Updated Name" }),
});
```

### 4. Refresh The Session

```ts
const csrfToken = readCookie("auth_csrf");

await fetch("/_auth/token", {
  method: "POST",
  credentials: "include",
  headers: {
    "X-CSRF-Token": csrfToken,
  },
});
```

Do not send the refresh token in the body for cookie-mode refresh.

### 5. Logout

```ts
const csrfToken = readCookie("auth_csrf");

await fetch("/_auth/logout", {
  method: "POST",
  credentials: "include",
  headers: {
    "X-CSRF-Token": csrfToken,
  },
});
```

Logout revokes the server-side session and clears the browser cookies.

## Frontend Rules

For browser consumers, treat these as hard requirements:

- use `credentials: "include"` on auth and app API requests
- send `X-CSRF-Token` on unsafe requests
- never persist access tokens or refresh tokens in `localStorage`,
  `sessionStorage`, IndexedDB, or other JavaScript-readable storage
- do not read or depend on access or refresh tokens in application code

Recommended but optional:

- send `X-Auth-Session-Transport: cookie` if you want explicit request intent
  in logs or mixed-client environments

The only cookie a browser client should read directly is the CSRF cookie. Use
the name that matches your environment-specific authSDK config.

## Suggested Frontend Helpers

```ts
export function readCookie(name: string): string {
  const prefix = `${name}=`;
  const value = document.cookie
    .split(";")
    .map((part) => part.trim())
    .find((part) => part.startsWith(prefix));

  return value ? decodeURIComponent(value.slice(prefix.length)) : "";
}
```

Wrap your app fetch client so it:

- always includes credentials
- reads the CSRF cookie for unsafe methods
- retries CSRF bootstrap when the CSRF cookie is missing

## Consumer Release Checklist

Every browser app should complete this checklist before shipping:

1. Add same-origin `/_auth` and `/api` proxy routes.
2. Enable `authSDK` browser sessions in the target environment.
3. Upgrade the downstream API to the SDK release with cookie extraction and
   `CookieCSRFMiddleware`.
4. Switch browser requests to `credentials: "include"`.
5. Remove all browser token persistence code.
6. Add CSRF propagation for unsafe requests.
7. Verify login, reload, refresh, logout, and revocation behavior end to end.

## Regression Tests To Add In The Consumer App

Add tests for:

- initial CSRF bootstrap
- login success with cookie transport
- page reload preserving auth state
- refresh flow after access-token expiry
- logout clearing browser auth state
- unsafe requests failing when CSRF is missing or mismatched

## Related Docs

- API contracts: `service-api.md`
- downstream SDK integration: `integrate-sdk.md`
- configuration reference: `configuration.md`
