# Testing Guide

This repository has three layers of validation:

- unit tests for isolated service, SDK, and helper behavior
- integration tests for routers, persistence, and multi-component flows
- load tests for selected high-throughput or safety-sensitive scenarios

## Test Layout

- `tests/unit/`
  service logic, middleware behavior, SDK behavior, helpers, and worker logic
- `tests/integration/`
  router contracts, DB-backed flows, auth lifecycles, and webhook system paths
- `loadtests/`
  Locust scenarios plus seed helpers and result artifacts

## Core Commands

Run all tests:

```bash
python -m pytest -q
```

Run lint and format checks:

```bash
python -m ruff check .
python -m black --check .
```

Validate migrations:

```bash
python -m alembic upgrade head --sql
python -m alembic upgrade head
```

Build both packages:

```bash
python -m build
python -m build sdk
```

## What CI Covers

The CI workflow verifies:

- Ruff
- Black
- unit and integration tests
- Alembic offline SQL generation
- Alembic online migration against Postgres
- service package build
- SDK package build
- SDK wheel import smoke test

See `.github/workflows/ci.yml` for the exact commands.

## Load Tests

`loadtests/README.md` documents the current Locust scenarios, including:

- login
- refresh
- OTP login
- action OTP
- machine-to-machine token issuance
- admin cursor pagination
- webhook delivery volume

Load testing is especially useful after changes to:

- auth token issuance
- OTP flows
- rate limiting
- admin list pagination
- webhook dispatch and retry behavior

## When To Add Tests

Add or update tests when you change:

- endpoint behavior or error contracts
- token claims or validation rules
- SDK middleware behavior
- admin-sensitive workflows
- persistence or migration logic
- background worker behavior

## Related Docs

- contributor workflow: `../CONTRIBUTING.md`
- local setup: `../DEVELOPMENT.md`
- load-test details: `../loadtests/README.md`
