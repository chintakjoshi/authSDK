# Step 14 Load Tests (Locust)

This folder now covers the full v2 Step 14 load-test surface:
- sustained `POST /auth/login`
- sustained `POST /auth/token` refresh
- OTP login flow under load, including one-time challenge isolation checks
- sensitive action OTP flow under load (`disable_otp` then `enable_otp`)
- M2M token issuance under load
- admin cursor-pagination reads under load with duplicate/missing-record checks
- webhook event volume runs

Use `AUTH_LOAD_SCENARIO` to activate one scenario per Locust run.

## Prerequisites

1. Start the full local stack:
```bash
docker compose -f docker/docker-compose.yml up -d
```

2. Ensure the host-side tools point at local Postgres:
```bash
set DATABASE__URL=postgresql+asyncpg://postgres@localhost:5432/auth_service
```

3. Seed the step-14 fixtures:
```bash
uv run --extra dev python -m loadtests.seed_step14_fixtures
```

This creates:
- one password-login load user
- one admin user
- an OTP-enabled user pool
- one M2M client and prints its secret

Optional webhook fixture:
```bash
uv run --extra dev python -m loadtests.seed_step14_fixtures --webhook-url https://webhook.site/<your-id>
```

Because SSRF protection intentionally blocks `localhost` and private IP ranges, the webhook-volume scenario needs a publicly reachable receiver.

## Common Environment

Base load credentials:
```bash
set AUTH_LOAD_EMAIL=loadtest@example.com
set AUTH_LOAD_PASSWORD=Password123!
set AUTH_LOAD_MAX_FAILURE_RATE_PCT=0.1
```

OTP pool:
```bash
set AUTH_LOAD_OTP_EMAIL_TEMPLATE=otp-load-{index}@example.com
set AUTH_LOAD_OTP_PASSWORD=Password123!
set AUTH_LOAD_OTP_USER_COUNT=100
set AUTH_LOAD_MAILHOG_API_URL=http://localhost:8025
```

Admin pagination:
```bash
set AUTH_LOAD_ADMIN_EMAIL=load-admin@example.com
set AUTH_LOAD_ADMIN_PASSWORD=Password123!
```

If you start the app with `ADMIN_API_KEY`, you can use that instead:
```bash
set AUTH_LOAD_ADMIN_API_KEY=<same-value-used-by-auth-service>
```

M2M:
```bash
set AUTH_LOAD_M2M_CLIENT_ID=<printed-by-seed-script>
set AUTH_LOAD_M2M_CLIENT_SECRET=<printed-by-seed-script>
set AUTH_LOAD_M2M_SCOPE=metrics:read
```

Webhook volume:
```bash
set AUTH_LOAD_WEBHOOK_ENDPOINT_ID=<printed-by-seed-script>
set AUTH_LOAD_MAX_WEBHOOK_QUEUE_DEPTH=200
```

## Baseline Login Run

```bash
set AUTH_LOAD_SCENARIO=login
uv run --extra dev locust -f loadtests/locustfile.py --host http://localhost:8000 --users 80 --spawn-rate 20 --run-time 5m --headless --only-summary
```

## Refresh Run

```bash
set AUTH_LOAD_SCENARIO=refresh
uv run --extra dev locust -f loadtests/locustfile.py --host http://localhost:8000 --users 80 --spawn-rate 20 --run-time 5m --headless --only-summary
```

## OTP Login Run

This run includes a one-time isolation check per virtual user: challenge A must reject user B's code.

```bash
set AUTH_LOAD_SCENARIO=otp-login
uv run --extra dev locust -f loadtests/locustfile.py --host http://localhost:8000 --users 20 --spawn-rate 5 --run-time 3m --headless --only-summary
```

## Sensitive Action OTP Run

```bash
set AUTH_LOAD_SCENARIO=action-otp
uv run --extra dev locust -f loadtests/locustfile.py --host http://localhost:8000 --users 10 --spawn-rate 3 --run-time 3m --headless --only-summary
```

## M2M Run

Capture the `sessions` row count before and after the run. It must remain unchanged.

```bash
set AUTH_LOAD_SCENARIO=m2m
uv run --extra dev locust -f loadtests/locustfile.py --host http://localhost:8000 --users 60 --spawn-rate 20 --run-time 5m --headless --only-summary
```

## Admin Pagination Run

Set the expected counts first so the run can check for missing records as well as duplicates.

```bash
set AUTH_LOAD_SCENARIO=admin-pagination
set AUTH_LOAD_EXPECTED_USER_COUNT=<count from database>
set AUTH_LOAD_EXPECTED_CLIENT_COUNT=<count from database>
uv run --extra dev locust -f loadtests/locustfile.py --host http://localhost:8000 --users 10 --spawn-rate 5 --run-time 2m --headless --only-summary
```

## Webhook Volume Run

Measure pending+failed delivery depth for the endpoint before and after the run to understand backlog growth.

```bash
set AUTH_LOAD_SCENARIO=webhook-volume
uv run --extra dev locust -f loadtests/locustfile.py --host http://localhost:8000 --users 40 --spawn-rate 10 --run-time 3m --headless --only-summary
```

## Rate-Limit Verification Run

```bash
set AUTH_LOAD_ALLOW_429=true
set AUTH_LOAD_REQUIRE_RATE_LIMIT=true
set AUTH_LOAD_MAX_FAILURE_RATE_PCT=1
set AUTH_LOAD_SCENARIO=login
uv run --extra dev locust -f loadtests/locustfile.py --host http://localhost:8000 --users 120 --spawn-rate 30 --run-time 3m --headless --only-summary
```

Pass conditions:
- overall failure rate is at or below the configured `AUTH_LOAD_MAX_FAILURE_RATE_PCT`
- when `AUTH_LOAD_REQUIRE_RATE_LIMIT=true`, at least one `429` is observed
- M2M runs leave session row counts unchanged
- admin pagination runs detect no duplicates or missing records
- webhook runs produce an acceptable backlog for the selected endpoint

## Environment Variables

- `DATABASE__URL`: DB URL used by the invariant checks and seed script
- `AUTH_LOAD_EMAIL`: primary password-login user
- `AUTH_LOAD_PASSWORD`: primary password-login password
- `AUTH_LOAD_OTP_EMAIL_TEMPLATE`: OTP pool email template; must include `{index}`
- `AUTH_LOAD_OTP_PASSWORD`: OTP pool password
- `AUTH_LOAD_OTP_USER_COUNT`: OTP pool size
- `AUTH_LOAD_MAILHOG_API_URL`: Mailhog API base URL
- `AUTH_LOAD_OTP_POLL_TIMEOUT_SECONDS`: max Mailhog poll time for one OTP email
- `AUTH_LOAD_ALLOW_429`: treat `429` as expected
- `AUTH_LOAD_REQUIRE_RATE_LIMIT`: fail if no `429` is observed
- `AUTH_LOAD_MAX_FAILURE_RATE_PCT`: allowed overall failure percent
- `AUTH_LOAD_SCENARIO`: one of `login`, `refresh`, `otp-login`, `action-otp`, `m2m`, `admin-pagination`, `webhook-volume`
- `AUTH_LOAD_ADMIN_API_KEY`: optional admin bootstrap key for `/admin/*`
- `AUTH_LOAD_ADMIN_EMAIL`: fallback admin login email
- `AUTH_LOAD_ADMIN_PASSWORD`: fallback admin login password
- `AUTH_LOAD_ADMIN_PAGE_LIMIT`: cursor page size used during admin list traversal
- `AUTH_LOAD_EXPECTED_USER_COUNT`: expected `/admin/users` total for missing-record detection
- `AUTH_LOAD_EXPECTED_CLIENT_COUNT`: expected `/admin/clients` total for missing-record detection
- `AUTH_LOAD_M2M_CLIENT_ID`: M2M client ID for `client_credentials`
- `AUTH_LOAD_M2M_CLIENT_SECRET`: M2M client secret
- `AUTH_LOAD_M2M_SCOPE`: optional requested scope string
- `AUTH_LOAD_WEBHOOK_ENDPOINT_ID`: endpoint id used for queue-depth tracking
