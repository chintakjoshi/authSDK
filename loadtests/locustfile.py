"""Locust scenarios for Step 14 login and refresh load testing."""

from __future__ import annotations

import os
from dataclasses import dataclass

from locust import HttpUser, between, events, task


def _env_bool(name: str, default: bool) -> bool:
    """Read a boolean environment flag."""
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _env_float(name: str, default: float) -> float:
    """Read a float environment variable with fallback."""
    value = os.environ.get(name)
    if value is None:
        return default
    try:
        return float(value)
    except ValueError:
        return default


@dataclass(frozen=True)
class LoadSettings:
    """Runtime settings for load-test behavior."""

    email: str
    password: str
    allow_429: bool
    require_rate_limit: bool
    max_failure_rate_pct: float


SETTINGS = LoadSettings(
    email=os.environ.get("AUTH_LOAD_EMAIL", "loadtest@example.com"),
    password=os.environ.get("AUTH_LOAD_PASSWORD", "Password123!"),
    allow_429=_env_bool("AUTH_LOAD_ALLOW_429", False),
    require_rate_limit=_env_bool("AUTH_LOAD_REQUIRE_RATE_LIMIT", False),
    max_failure_rate_pct=_env_float("AUTH_LOAD_MAX_FAILURE_RATE_PCT", 0.1),
)

_rate_limit_observed = False


def _is_valid_token_payload(payload: dict[str, object]) -> bool:
    """Validate auth token response shape."""
    access_token = payload.get("access_token")
    refresh_token = payload.get("refresh_token")
    token_type = payload.get("token_type")
    return bool(access_token) and bool(refresh_token) and token_type == "bearer"


class LoginFlowUser(HttpUser):
    """Sustained login scenario to measure auth/login throughput and failures."""

    wait_time = between(0.05, 0.2)
    weight = 1

    @task
    def login(self) -> None:
        """Call login endpoint continuously using configured credentials."""
        global _rate_limit_observed
        with self.client.post(
            "/auth/login",
            json={"email": SETTINGS.email, "password": SETTINGS.password},
            name="POST /auth/login",
            catch_response=True,
        ) as response:
            if response.status_code == 200:
                payload = response.json()
                if _is_valid_token_payload(payload):
                    response.success()
                    return
                response.failure("200 without expected token payload shape")
                return

            if response.status_code == 429 and SETTINGS.allow_429:
                _rate_limit_observed = True
                response.success()
                return

            response.failure(f"unexpected status={response.status_code}")


class RefreshFlowUser(HttpUser):
    """Sustained refresh scenario to measure auth/token throughput and failures."""

    wait_time = between(0.05, 0.2)
    weight = 2

    def __init__(self, environment) -> None:
        super().__init__(environment)
        self._refresh_token: str | None = None

    def on_start(self) -> None:
        """Authenticate once to bootstrap refresh token for this virtual user."""
        response = self.client.post(
            "/auth/login",
            json={"email": SETTINGS.email, "password": SETTINGS.password},
            name="POST /auth/login [bootstrap]",
        )
        if response.status_code != 200:
            print(f"[loadtest] refresh bootstrap failed with status={response.status_code}")
            return
        payload = response.json()
        refresh_token = payload.get("refresh_token")
        self._refresh_token = str(refresh_token) if refresh_token else None

    @task
    def refresh(self) -> None:
        """Rotate refresh token repeatedly using current token state."""
        global _rate_limit_observed
        if not self._refresh_token:
            self.on_start()
            if not self._refresh_token:
                return

        with self.client.post(
            "/auth/token",
            json={"refresh_token": self._refresh_token},
            name="POST /auth/token",
            catch_response=True,
        ) as response:
            if response.status_code == 200:
                payload = response.json()
                if _is_valid_token_payload(payload):
                    self._refresh_token = str(payload["refresh_token"])
                    response.success()
                    return
                response.failure("200 without expected token payload shape")
                return

            if response.status_code == 429 and SETTINGS.allow_429:
                _rate_limit_observed = True
                response.success()
                return

            response.failure(f"unexpected status={response.status_code}")


@events.quitting.add_listener
def _on_quitting(environment, **_kwargs) -> None:
    """Enforce Step 14 pass/fail thresholds at test shutdown."""
    failure_rate_pct = environment.stats.total.fail_ratio * 100.0
    if SETTINGS.max_failure_rate_pct >= 0 and failure_rate_pct > SETTINGS.max_failure_rate_pct:
        print(
            f"[loadtest] failure rate {failure_rate_pct:.3f}% exceeded "
            f"max {SETTINGS.max_failure_rate_pct:.3f}%"
        )
        environment.process_exit_code = 1

    if SETTINGS.require_rate_limit and not _rate_limit_observed:
        print("[loadtest] expected at least one 429 response but none were observed")
        environment.process_exit_code = 1
