# Contributing

This repository ships both a deployable auth service and a reusable SDK. Good
changes keep those two surfaces aligned: code, tests, and documentation should
move together.

## Before You Start

- read `README.md` for the repo overview
- read `DEVELOPMENT.md` for local setup
- read `docs/README.md` for the full docs map

## Development Expectations

When you make a change:

- keep docs in sync with behavior
- add or update tests for user-visible logic
- preserve compatibility between the service and the SDK
- avoid introducing configuration that is only documented in code

## Recommended Workflow

1. Create or update your local environment from `.env-sample`.
2. Run the stack or the dependencies you need.
3. Make the smallest coherent change set you can.
4. Run the relevant checks.
5. Update docs if behavior, configuration, or operator workflows changed.

## Quality Gates

Run these before opening a PR:

```bash
python -m ruff check .
python -m black --check .
python -m pytest -q
python -m alembic upgrade head --sql
python -m build
python -m build sdk
```

If you use `uv`, equivalent commands are fine.

## Code Organization

- `app/`: service code
- `sdk/`: client-side integration package
- `tests/unit/`: fast isolated coverage
- `tests/integration/`: DB, Redis, router, and workflow coverage
- `loadtests/`: Locust scenarios and seed helpers
- `docs/`: maintainer and consumer documentation

## Database Changes

When you change models or persistence behavior:

- add or update an Alembic migration in `migrations/versions/`
- verify `python -m alembic upgrade head`
- verify `python -m alembic upgrade head --sql`
- document any new environment or operator steps

## Documentation Changes

Update documentation whenever you change:

- endpoint behavior or response contracts
- configuration keys or defaults
- background worker behavior
- security assumptions
- contributor or deployment workflows

The goal is that a new engineer can trust the docs without reading the entire
codebase first.

## Pull Request Checklist

- behavior is covered by tests or the gap is explicitly called out
- docs and examples match the code
- new config is represented in `.env-sample` when applicable
- migrations are included when schema changes require them
- service and SDK impacts were both considered
