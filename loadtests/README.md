# Step 14 Load Tests (Locust)

This folder contains Locust scenarios for:
- sustained `POST /auth/login` load
- sustained `POST /auth/token` refresh load

## Prerequisites

1. Start service and dependencies:
```bash
docker compose -f docker/docker-compose.yml up -d
```

2. Ensure schema is current:
```bash
alembic upgrade head
```

3. Seed a password user used by Locust:
```bash
python -m loadtests.seed_load_user --email loadtest@example.com --password Password123!
```

4. Install Locust:
```bash
python -m pip install "locust==2.31.8"
```

## Baseline Throughput Run

Headless example:
```bash
set AUTH_LOAD_EMAIL=loadtest@example.com
set AUTH_LOAD_PASSWORD=Password123!
set AUTH_LOAD_ALLOW_429=false
set AUTH_LOAD_MAX_FAILURE_RATE_PCT=0.1
locust -f loadtests/locustfile.py --host http://localhost:8000 --users 80 --spawn-rate 20 --run-time 5m --headless --only-summary
```

Pass condition:
- overall failure rate <= `0.1%` (enforced by `AUTH_LOAD_MAX_FAILURE_RATE_PCT`)

## Rate-Limit Verification Run

This run verifies that rate limiting engages under concurrency.

```bash
set AUTH_LOAD_EMAIL=loadtest@example.com
set AUTH_LOAD_PASSWORD=Password123!
set AUTH_LOAD_ALLOW_429=true
set AUTH_LOAD_REQUIRE_RATE_LIMIT=true
set AUTH_LOAD_MAX_FAILURE_RATE_PCT=1
locust -f loadtests/locustfile.py --host http://localhost:8000 --users 120 --spawn-rate 30 --run-time 3m --headless --only-summary
```

Pass conditions:
- at least one `429` response observed (enforced by `AUTH_LOAD_REQUIRE_RATE_LIMIT=true`)
- non-rate-limit failure rate remains below configured threshold

## Environment Variables

- `AUTH_LOAD_EMAIL`: login email (default `loadtest@example.com`)
- `AUTH_LOAD_PASSWORD`: login password (default `Password123!`)
- `AUTH_LOAD_ALLOW_429`: treat `429` as expected, not failure (`true/false`)
- `AUTH_LOAD_REQUIRE_RATE_LIMIT`: fail run if no `429` occurs (`true/false`)
- `AUTH_LOAD_MAX_FAILURE_RATE_PCT`: max allowed overall failure percent (default `0.1`)
