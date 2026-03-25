# Load Tests

This directory contains Locust scenarios, seed helpers, and result artifacts for
the auth service.

Current scenario coverage:

- password login
- refresh token issuance
- OTP login flow
- step-up action OTP flow
- machine-to-machine token issuance
- admin cursor pagination
- webhook delivery volume

Use `AUTH_LOAD_SCENARIO` to select one scenario per run.

## Related Docs

- repo overview: `../README.md`
- development workflow: `../DEVELOPMENT.md`
- testing guide: `../docs/testing.md`
- operations guide: `../docs/operations.md`

## Prerequisites

1. Start the local stack:

```bash
docker compose -f docker/docker-compose.yml up -d
```

2. Point host-side tools at the local database:

```powershell
$env:DATABASE__URL="postgresql+asyncpg://postgres:postgres@localhost:5432/auth_service"
```

3. Seed fixtures:

```bash
uv run --extra dev python -m loadtests.seed_load_fixtures
```

Optional public webhook fixture:

```bash
uv run --extra dev python -m loadtests.seed_load_fixtures --webhook-url https://webhook.site/<your-id>
```

The webhook volume scenario requires a publicly reachable receiver because the
service intentionally rejects localhost and private-network destinations.

## Common Environment

Base login:

```powershell
$env:AUTH_LOAD_EMAIL="loadtest@example.com"
$env:AUTH_LOAD_PASSWORD="Password123!"
$env:AUTH_LOAD_MAX_FAILURE_RATE_PCT="0.1"
```

OTP pool:

```powershell
$env:AUTH_LOAD_OTP_EMAIL_TEMPLATE="otp-load-{index}@example.com"
$env:AUTH_LOAD_OTP_PASSWORD="Password123!"
$env:AUTH_LOAD_OTP_USER_COUNT="100"
$env:AUTH_LOAD_MAILHOG_API_URL="http://localhost:8025"
```

Admin pagination:

```powershell
$env:AUTH_LOAD_ADMIN_EMAIL="load-admin@example.com"
$env:AUTH_LOAD_ADMIN_PASSWORD="Password123!"
```

Optional bootstrap access instead of admin login:

```powershell
$env:AUTH_LOAD_ADMIN_API_KEY="<same-value-as-ADMIN_API_KEY>"
```

M2M:

```powershell
$env:AUTH_LOAD_M2M_CLIENT_ID="<seeded-client-id>"
$env:AUTH_LOAD_M2M_CLIENT_SECRET="<seeded-client-secret>"
$env:AUTH_LOAD_M2M_SCOPE="metrics:read"
```

Webhook volume:

```powershell
$env:AUTH_LOAD_WEBHOOK_ENDPOINT_ID="<seeded-endpoint-id>"
$env:AUTH_LOAD_MAX_WEBHOOK_QUEUE_DEPTH="200"
```

## Example Runs

The examples below use bash-style environment assignment. In PowerShell, replace
`export NAME=value` with `$env:NAME="value"`.

Login:

```bash
export AUTH_LOAD_SCENARIO=login
uv run --extra dev locust -f loadtests/locustfile.py --host http://localhost:8000 --users 80 --spawn-rate 20 --run-time 5m --headless --only-summary
```

Refresh:

```bash
export AUTH_LOAD_SCENARIO=refresh
uv run --extra dev locust -f loadtests/locustfile.py --host http://localhost:8000 --users 80 --spawn-rate 20 --run-time 5m --headless --only-summary
```

OTP login:

```bash
export AUTH_LOAD_SCENARIO=otp-login
uv run --extra dev locust -f loadtests/locustfile.py --host http://localhost:8000 --users 20 --spawn-rate 5 --run-time 3m --headless --only-summary
```

Action OTP:

```bash
export AUTH_LOAD_SCENARIO=action-otp
uv run --extra dev locust -f loadtests/locustfile.py --host http://localhost:8000 --users 10 --spawn-rate 3 --run-time 3m --headless --only-summary
```

M2M:

```bash
export AUTH_LOAD_SCENARIO=m2m
uv run --extra dev locust -f loadtests/locustfile.py --host http://localhost:8000 --users 60 --spawn-rate 20 --run-time 5m --headless --only-summary
```

Admin pagination:

```bash
export AUTH_LOAD_SCENARIO=admin-pagination
export AUTH_LOAD_EXPECTED_USER_COUNT=<user-count>
export AUTH_LOAD_EXPECTED_CLIENT_COUNT=<client-count>
uv run --extra dev locust -f loadtests/locustfile.py --host http://localhost:8000 --users 10 --spawn-rate 5 --run-time 2m --headless --only-summary
```

Webhook volume:

```bash
export AUTH_LOAD_SCENARIO=webhook-volume
uv run --extra dev locust -f loadtests/locustfile.py --host http://localhost:8000 --users 40 --spawn-rate 10 --run-time 3m --headless --only-summary
```

Rate-limit verification:

```powershell
$env:AUTH_LOAD_ALLOW_429="true"
$env:AUTH_LOAD_REQUIRE_RATE_LIMIT="true"
$env:AUTH_LOAD_MAX_FAILURE_RATE_PCT="1"
$env:AUTH_LOAD_SCENARIO="login"
uv run --extra dev locust -f loadtests/locustfile.py --host http://localhost:8000 --users 120 --spawn-rate 30 --run-time 3m --headless --only-summary
```

## Pass Conditions

- overall failure rate stays within `AUTH_LOAD_MAX_FAILURE_RATE_PCT`
- rate-limit verification observes at least one `429` when required
- machine-to-machine runs do not create user sessions
- admin pagination runs show no duplicates or missing records
- webhook backlog remains acceptable for the selected endpoint

## Additional Environment Variables

- `AUTH_LOAD_OTP_POLL_TIMEOUT_SECONDS`
  maximum time to wait for a Mailhog OTP email
- `AUTH_LOAD_ADMIN_PAGE_LIMIT`
  page size used for admin cursor traversal
- `AUTH_LOAD_EXPECTED_USER_COUNT`
  expected `/admin/users` total for missing-record detection
- `AUTH_LOAD_EXPECTED_CLIENT_COUNT`
  expected `/admin/clients` total for missing-record detection
- `AUTH_LOAD_ADMIN_API_KEY`
  optional development bootstrap key for admin scenarios
