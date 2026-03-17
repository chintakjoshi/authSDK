"""Locust scenarios for Step 14 v2 load testing."""

from __future__ import annotations

import itertools
import os
import re
import threading
import time
from dataclasses import dataclass
from urllib.parse import urlencode
from uuid import UUID

import httpx
from locust import HttpUser, between, events, tag, task
from locust.exception import StopUser


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


def _env_int(name: str, default: int) -> int:
    """Read an integer environment variable with fallback."""
    value = os.environ.get(name)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        return default


@dataclass(frozen=True)
class LoadSettings:
    """Runtime settings for step-14 load-test behavior."""

    email: str
    password: str
    otp_email_template: str
    otp_password: str
    otp_user_count: int
    otp_poll_timeout_seconds: float
    mailhog_api_url: str
    allow_429: bool
    require_rate_limit: bool
    max_failure_rate_pct: float
    expected_user_count: int
    expected_client_count: int
    admin_api_key: str | None
    admin_email: str | None
    admin_password: str | None
    admin_page_limit: int
    m2m_client_id: str | None
    m2m_client_secret: str | None
    m2m_scope: str | None
    webhook_endpoint_id: str | None
    max_webhook_queue_depth: int


SETTINGS = LoadSettings(
    email=os.environ.get("AUTH_LOAD_EMAIL", "loadtest@example.com"),
    password=os.environ.get("AUTH_LOAD_PASSWORD", "Password123!"),
    otp_email_template=os.environ.get(
        "AUTH_LOAD_OTP_EMAIL_TEMPLATE", "otp-load-{index}@example.com"
    ),
    otp_password=os.environ.get("AUTH_LOAD_OTP_PASSWORD", "Password123!"),
    otp_user_count=_env_int("AUTH_LOAD_OTP_USER_COUNT", 100),
    otp_poll_timeout_seconds=_env_float("AUTH_LOAD_OTP_POLL_TIMEOUT_SECONDS", 10.0),
    mailhog_api_url=os.environ.get("AUTH_LOAD_MAILHOG_API_URL", "http://localhost:8025"),
    allow_429=_env_bool("AUTH_LOAD_ALLOW_429", False),
    require_rate_limit=_env_bool("AUTH_LOAD_REQUIRE_RATE_LIMIT", False),
    max_failure_rate_pct=_env_float("AUTH_LOAD_MAX_FAILURE_RATE_PCT", 0.1),
    expected_user_count=_env_int("AUTH_LOAD_EXPECTED_USER_COUNT", -1),
    expected_client_count=_env_int("AUTH_LOAD_EXPECTED_CLIENT_COUNT", -1),
    admin_api_key=os.environ.get("AUTH_LOAD_ADMIN_API_KEY"),
    admin_email=os.environ.get("AUTH_LOAD_ADMIN_EMAIL"),
    admin_password=os.environ.get("AUTH_LOAD_ADMIN_PASSWORD"),
    admin_page_limit=max(1, min(_env_int("AUTH_LOAD_ADMIN_PAGE_LIMIT", 25), 200)),
    m2m_client_id=os.environ.get("AUTH_LOAD_M2M_CLIENT_ID"),
    m2m_client_secret=os.environ.get("AUTH_LOAD_M2M_CLIENT_SECRET"),
    m2m_scope=os.environ.get("AUTH_LOAD_M2M_SCOPE"),
    webhook_endpoint_id=os.environ.get("AUTH_LOAD_WEBHOOK_ENDPOINT_ID"),
    max_webhook_queue_depth=_env_int("AUTH_LOAD_MAX_WEBHOOK_QUEUE_DEPTH", -1),
)
ACTIVE_SCENARIO = os.environ.get("AUTH_LOAD_SCENARIO", "all").strip().lower()

_OTP_CODE_PATTERN = re.compile(r"\b(\d{4,12})\b")
_MAILHOG_TO_PATTERN = re.compile(r"<([^>]+)>")
_rate_limit_observed = False
_otp_pair_counter = itertools.count(1, 2)
_otp_pair_lock = threading.Lock()
_admin_pagination_error: str | None = None


def _is_valid_token_payload(payload: dict[str, object]) -> bool:
    """Validate login/refresh token response shape."""
    access_token = payload.get("access_token")
    refresh_token = payload.get("refresh_token")
    token_type = payload.get("token_type", "bearer")
    return bool(access_token) and bool(refresh_token) and str(token_type).lower() == "bearer"


def _is_valid_m2m_payload(payload: dict[str, object]) -> bool:
    """Validate client-credentials response shape."""
    access_token = payload.get("access_token")
    token_type = payload.get("token_type")
    expires_in = payload.get("expires_in")
    return (
        bool(access_token) and str(token_type).lower() == "bearer" and isinstance(expires_in, int)
    )


def _otp_email_for(index: int) -> str:
    """Render the configured OTP load-user email template."""
    return SETTINGS.otp_email_template.format(index=index)


def _selected_tags(environment) -> set[str]:
    """Return active Locust tag filters as a normalized set."""
    parsed_options = getattr(environment, "parsed_options", None)
    if parsed_options is None:
        return set()
    raw_tags = getattr(parsed_options, "tags", None) or []
    if isinstance(raw_tags, str):
        raw_tags = [raw_tags]
    return {str(item).strip() for item in raw_tags if str(item).strip()}


class MailhogInbox:
    """Poll Mailhog API for per-recipient OTP messages."""

    def __init__(self, api_url: str) -> None:
        self._api_url = api_url.rstrip("/")
        self._client = httpx.Client(timeout=5.0)
        self._seen_ids: dict[str, set[str]] = {}

    def close(self) -> None:
        """Close underlying HTTP client."""
        self._client.close()

    def fetch_latest_code(self, email: str, *, timeout_seconds: float) -> str:
        """Poll Mailhog until a new OTP code arrives for the recipient."""
        deadline = time.monotonic() + timeout_seconds
        seen = self._seen_ids.setdefault(email.lower(), set())
        while time.monotonic() < deadline:
            code = self._find_new_code(email=email, seen=seen)
            if code is not None:
                return code
            time.sleep(0.25)
        raise RuntimeError(f"No OTP email observed for {email!r} within {timeout_seconds:.1f}s.")

    def _find_new_code(self, *, email: str, seen: set[str]) -> str | None:
        """Return the newest unseen OTP code for the recipient."""
        response = self._client.get(f"{self._api_url}/api/v2/messages")
        response.raise_for_status()
        items = response.json().get("items", [])
        target = email.strip().lower()
        for item in items:
            message_id = str(item.get("ID", ""))
            if not message_id or message_id in seen:
                continue
            headers = item.get("Content", {}).get("Headers", {})
            recipients = headers.get("To", [])
            if not any(self._recipient_matches(target, value) for value in recipients):
                continue
            body = str(item.get("Content", {}).get("Body", ""))
            match = _OTP_CODE_PATTERN.search(body)
            if match is None:
                continue
            seen.add(message_id)
            return match.group(1)
        return None

    @staticmethod
    def _recipient_matches(target: str, raw_value: str) -> bool:
        """Return True when one Mailhog To-header value contains the target email."""
        normalized = raw_value.strip().lower()
        if normalized == target:
            return True
        extracted = _MAILHOG_TO_PATTERN.search(normalized)
        return extracted is not None and extracted.group(1) == target


class BaseLoadUser(HttpUser):
    """Base class for step-14 Locust users with shared helpers."""

    abstract = True
    wait_time = between(0.05, 0.2)

    def fail_start(self, message: str) -> None:
        """Stop the virtual user and mark the run as failed."""
        print(f"[loadtest] {message}")
        self.environment.process_exit_code = 1
        raise StopUser(message)

    def allow_rate_limit_or_fail(self, response, *, context: str) -> bool:
        """Treat 429 as expected only when the run is configured for it."""
        global _rate_limit_observed
        if response.status_code == 429 and SETTINGS.allow_429:
            _rate_limit_observed = True
            response.success()
            return True
        response.failure(f"{context}: unexpected status={response.status_code}")
        return False


class LoginFlowUser(BaseLoadUser):
    """Sustained login scenario to measure password-login throughput."""

    weight = 1

    @tag("login")
    @task
    def login(self) -> None:
        """Call the login endpoint continuously using configured credentials."""
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
                response.failure("login returned 200 without access+refresh tokens")
                return
            self.allow_rate_limit_or_fail(response, context="login")


class RefreshFlowUser(BaseLoadUser):
    """Sustained refresh scenario using one rotating refresh token per user."""

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
            self.fail_start(f"refresh bootstrap failed with status={response.status_code}")
        payload = response.json()
        refresh_token = payload.get("refresh_token")
        if not refresh_token:
            self.fail_start("refresh bootstrap returned no refresh_token")
        self._refresh_token = str(refresh_token)

    @tag("refresh")
    @task
    def refresh(self) -> None:
        """Rotate refresh token repeatedly using the current token state."""
        if not self._refresh_token:
            self.fail_start("refresh token missing during refresh scenario")

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
                response.failure("refresh returned 200 without access+refresh tokens")
                return
            self.allow_rate_limit_or_fail(response, context="refresh")


class OTPLoginFlowUser(BaseLoadUser):
    """Exercise OTP login under load and verify challenge isolation once per user."""

    weight = 1

    def __init__(self, environment) -> None:
        super().__init__(environment)
        self._mailhog = MailhogInbox(SETTINGS.mailhog_api_url)
        self._primary_email = ""
        self._secondary_email = ""

    def on_start(self) -> None:
        """Assign a stable account pair and validate one isolation attempt."""
        if SETTINGS.otp_user_count < 2:
            self.fail_start("AUTH_LOAD_OTP_USER_COUNT must be at least 2 for OTP isolation.")
        with _otp_pair_lock:
            first_index = next(_otp_pair_counter)
        second_index = first_index + 1
        if second_index > SETTINGS.otp_user_count:
            self.fail_start(
                "OTP pool exhausted. Increase AUTH_LOAD_OTP_USER_COUNT for the selected user count."
            )
        self._primary_email = _otp_email_for(first_index)
        self._secondary_email = _otp_email_for(second_index)
        self._run_isolation_check_once()

    def on_stop(self) -> None:
        """Close Mailhog client when the virtual user stops."""
        self._mailhog.close()

    def _run_isolation_check_once(self) -> None:
        """Assert that one user's OTP code cannot satisfy another user's challenge."""
        challenge_a = self._start_login(self._primary_email)
        challenge_b = self._start_login(self._secondary_email)
        code_a = self._mailhog.fetch_latest_code(
            self._primary_email, timeout_seconds=SETTINGS.otp_poll_timeout_seconds
        )
        code_b = self._mailhog.fetch_latest_code(
            self._secondary_email, timeout_seconds=SETTINGS.otp_poll_timeout_seconds
        )

        with self.client.post(
            "/auth/otp/verify/login",
            json={"challenge_token": challenge_a, "code": code_b},
            name="POST /auth/otp/verify/login [isolation]",
            catch_response=True,
        ) as mismatch:
            if mismatch.status_code == 401 and mismatch.json().get("code") == "invalid_otp":
                mismatch.success()
            else:
                mismatch.failure("OTP isolation check failed: cross-user code was accepted.")
                self.fail_start(
                    "OTP isolation check failed: challenge A unexpectedly accepted user B's code."
                )

        self._verify_login_success(challenge_a, code_a, label="[isolation A]")
        self._verify_login_success(challenge_b, code_b, label="[isolation B]")

    def _start_login(self, email: str) -> str:
        """Start password login and return the OTP challenge token."""
        response = self.client.post(
            "/auth/login",
            json={"email": email, "password": SETTINGS.otp_password},
            name="POST /auth/login [otp]",
        )
        if response.status_code != 200:
            self.fail_start(
                f"OTP login bootstrap for {email} failed with status={response.status_code}"
            )
        payload = response.json()
        if payload.get("otp_required") is not True or not payload.get("challenge_token"):
            self.fail_start(f"OTP login bootstrap for {email} returned no challenge_token.")
        return str(payload["challenge_token"])

    def _verify_login_success(self, challenge_token: str, code: str, *, label: str = "") -> str:
        """Submit OTP and return the access token from a successful login."""
        response = self.client.post(
            "/auth/otp/verify/login",
            json={"challenge_token": challenge_token, "code": code},
            name=f"POST /auth/otp/verify/login {label}".strip(),
        )
        if response.status_code != 200:
            self.fail_start(f"OTP verify {label} failed with status={response.status_code}")
        payload = response.json()
        if not _is_valid_token_payload(payload):
            self.fail_start(f"OTP verify {label} returned invalid token payload")
        return str(payload["access_token"])

    @tag("otp-login")
    @task
    def otp_login(self) -> None:
        """Run the happy-path OTP login flow for one assigned account."""
        with self.client.post(
            "/auth/login",
            json={"email": self._primary_email, "password": SETTINGS.otp_password},
            name="POST /auth/login [otp]",
            catch_response=True,
        ) as response:
            if response.status_code != 200:
                response.failure(f"otp login returned status={response.status_code}")
                return
            payload = response.json()
            challenge_token = payload.get("challenge_token")
            if payload.get("otp_required") is not True or not challenge_token:
                response.failure("otp login did not return an OTP challenge")
                return
            response.success()

        try:
            code = self._mailhog.fetch_latest_code(
                self._primary_email, timeout_seconds=SETTINGS.otp_poll_timeout_seconds
            )
        except Exception as exc:
            self.fail_start(str(exc))

        with self.client.post(
            "/auth/otp/verify/login",
            json={"challenge_token": challenge_token, "code": code},
            name="POST /auth/otp/verify/login",
            catch_response=True,
        ) as verify_response:
            if verify_response.status_code == 200 and _is_valid_token_payload(
                verify_response.json()
            ):
                verify_response.success()
                return
            verify_response.failure(
                f"otp verify returned status={verify_response.status_code} or invalid payload"
            )


class ActionOTPFlowUser(BaseLoadUser):
    """Exercise request+verify+submit action-token flows under load."""

    weight = 1

    def __init__(self, environment) -> None:
        super().__init__(environment)
        self._mailhog = MailhogInbox(SETTINGS.mailhog_api_url)
        self._email = ""

    def on_start(self) -> None:
        """Assign one OTP-enabled user account."""
        if SETTINGS.otp_user_count < 1:
            self.fail_start("AUTH_LOAD_OTP_USER_COUNT must be at least 1 for action OTP tests.")
        with _otp_pair_lock:
            user_index = next(_otp_pair_counter)
        if user_index > SETTINGS.otp_user_count:
            self.fail_start(
                "OTP pool exhausted. Increase AUTH_LOAD_OTP_USER_COUNT for the selected user count."
            )
        self._email = _otp_email_for(user_index)

    def on_stop(self) -> None:
        """Close Mailhog client when the virtual user stops."""
        self._mailhog.close()

    def _login_with_otp(self) -> str:
        """Complete OTP login and return the access token."""
        response = self.client.post(
            "/auth/login",
            json={"email": self._email, "password": SETTINGS.otp_password},
            name="POST /auth/login [action otp]",
        )
        if response.status_code != 200:
            self.fail_start(f"action login failed with status={response.status_code}")
        payload = response.json()
        challenge_token = payload.get("challenge_token")
        if payload.get("otp_required") is not True or not challenge_token:
            self.fail_start("action login did not return challenge_token")
        code = self._mailhog.fetch_latest_code(
            self._email, timeout_seconds=SETTINGS.otp_poll_timeout_seconds
        )
        verify = self.client.post(
            "/auth/otp/verify/login",
            json={"challenge_token": challenge_token, "code": code},
            name="POST /auth/otp/verify/login [action otp]",
        )
        if verify.status_code != 200 or not _is_valid_token_payload(verify.json()):
            self.fail_start(f"action login OTP verify failed with status={verify.status_code}")
        return str(verify.json()["access_token"])

    def _complete_action(self, access_token: str, *, action: str, submit_path: str) -> None:
        """Request, verify, and submit one OTP-gated action."""
        headers = {"Authorization": f"Bearer {access_token}"}
        request_response = self.client.post(
            "/auth/otp/request/action",
            json={"action": action},
            headers=headers,
            name="POST /auth/otp/request/action",
        )
        if request_response.status_code != 200:
            self.fail_start(
                f"request action OTP for {action} failed with {request_response.status_code}"
            )
        code = self._mailhog.fetch_latest_code(
            self._email, timeout_seconds=SETTINGS.otp_poll_timeout_seconds
        )
        verify_response = self.client.post(
            "/auth/otp/verify/action",
            json={"action": action, "code": code},
            headers=headers,
            name="POST /auth/otp/verify/action",
        )
        if verify_response.status_code != 200:
            self.fail_start(
                f"verify action OTP for {action} failed with {verify_response.status_code}"
            )
        action_token = verify_response.json().get("action_token")
        if not action_token:
            self.fail_start(f"verify action OTP for {action} returned no action_token")
        submit_response = self.client.post(
            submit_path,
            headers={**headers, "X-Action-Token": str(action_token)},
            name=f"POST {submit_path}",
        )
        if submit_response.status_code != 200:
            self.fail_start(f"submit {action} failed with status={submit_response.status_code}")

    @tag("action-otp")
    @task
    def action_otp_flow(self) -> None:
        """Disable and then re-enable OTP using action tokens."""
        access_token = self._login_with_otp()
        self._complete_action(access_token, action="disable_otp", submit_path="/auth/otp/disable")
        self._complete_action(access_token, action="enable_otp", submit_path="/auth/otp/enable")


class M2MTokenUser(BaseLoadUser):
    """Sustained M2M token issuance."""

    weight = 1

    def on_start(self) -> None:
        """Validate required M2M credentials."""
        if not SETTINGS.m2m_client_id or not SETTINGS.m2m_client_secret:
            self.fail_start(
                "M2M scenario requires AUTH_LOAD_M2M_CLIENT_ID and AUTH_LOAD_M2M_CLIENT_SECRET."
            )

    @tag("m2m")
    @task
    def issue_m2m_token(self) -> None:
        """Issue client-credentials tokens without creating session rows."""
        body = {
            "grant_type": "client_credentials",
            "client_id": SETTINGS.m2m_client_id or "",
            "client_secret": SETTINGS.m2m_client_secret or "",
        }
        if SETTINGS.m2m_scope:
            body["scope"] = SETTINGS.m2m_scope

        with self.client.post(
            "/auth/token",
            data=urlencode(body),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            name="POST /auth/token [m2m]",
            catch_response=True,
        ) as response:
            if response.status_code == 200 and _is_valid_m2m_payload(response.json()):
                response.success()
                return
            response.failure(f"m2m token issuance returned status={response.status_code}")


class AdminPaginationUser(BaseLoadUser):
    """Read admin cursor-paginated endpoints under concurrent load."""

    weight = 1

    def __init__(self, environment) -> None:
        super().__init__(environment)
        self._admin_headers: dict[str, str] | None = None

    def on_start(self) -> None:
        """Resolve admin credentials for cursor-pagination checks."""
        if SETTINGS.admin_api_key:
            self._admin_headers = {"X-Admin-API-Key": SETTINGS.admin_api_key}
            return
        if SETTINGS.admin_email and SETTINGS.admin_password:
            response = self.client.post(
                "/auth/login",
                json={"email": SETTINGS.admin_email, "password": SETTINGS.admin_password},
                name="POST /auth/login [admin bootstrap]",
            )
            if response.status_code != 200 or not _is_valid_token_payload(response.json()):
                self.fail_start("Admin login bootstrap failed for pagination scenario.")
            self._admin_headers = {"Authorization": f"Bearer {response.json()['access_token']}"}
            return
        self.fail_start(
            "Admin pagination scenario requires AUTH_LOAD_ADMIN_API_KEY or admin login credentials."
        )

    def _assert_full_cursor_scan(self, *, path: str, item_key: str, expected_total: int) -> None:
        """Traverse one cursor-paginated endpoint and assert no duplicates or omissions."""
        cursor: str | None = None
        seen_ids: list[str] = []
        while True:
            params = {"limit": SETTINGS.admin_page_limit}
            if cursor:
                params["cursor"] = cursor
            response = self.client.get(path, headers=self._admin_headers, params=params, name=path)
            if response.status_code != 200:
                raise RuntimeError(f"{path} returned status={response.status_code}")
            payload = response.json()
            for item in payload.get("data", []):
                value = item.get(item_key)
                if value is None:
                    raise RuntimeError(f"{path} item missing {item_key}")
                seen_ids.append(str(value))
            if not payload.get("has_more"):
                break
            cursor = payload.get("next_cursor")
            if not cursor:
                raise RuntimeError(f"{path} indicated has_more without next_cursor")

        if len(seen_ids) != len(set(seen_ids)):
            raise RuntimeError(f"{path} returned duplicate records across cursor pages")
        if expected_total >= 0 and len(seen_ids) != expected_total:
            raise RuntimeError(
                f"{path} returned {len(seen_ids)} records but expected {expected_total}"
            )

    @tag("admin-pagination")
    @task
    def paginate_admin_lists(self) -> None:
        """Validate cursor pagination for admin user and client listings."""
        global _admin_pagination_error
        try:
            expected_users = SETTINGS.expected_user_count
            expected_clients = SETTINGS.expected_client_count
            self._assert_full_cursor_scan(
                path="/admin/users", item_key="id", expected_total=expected_users
            )
            self._assert_full_cursor_scan(
                path="/admin/clients", item_key="id", expected_total=expected_clients
            )
        except Exception as exc:
            _admin_pagination_error = str(exc)
            raise


class WebhookVolumeUser(BaseLoadUser):
    """Generate event volume for webhook delivery."""

    weight = 1

    def on_start(self) -> None:
        """Validate configured endpoint id once."""
        if not SETTINGS.webhook_endpoint_id:
            self.fail_start("Webhook scenario requires AUTH_LOAD_WEBHOOK_ENDPOINT_ID.")
        try:
            UUID(SETTINGS.webhook_endpoint_id)
        except ValueError as exc:
            self.fail_start(f"Invalid AUTH_LOAD_WEBHOOK_ENDPOINT_ID: {exc}")

    @tag("webhook-volume")
    @task
    def login_and_measure_queue_depth(self) -> None:
        """Generate webhook-producing login traffic."""
        response = self.client.post(
            "/auth/login",
            json={"email": SETTINGS.email, "password": SETTINGS.password},
            name="POST /auth/login [webhook volume]",
        )
        if response.status_code != 200 or not _is_valid_token_payload(response.json()):
            raise RuntimeError(f"webhook login returned status={response.status_code}")


def _scenario_enabled(name: str) -> bool:
    """Return True when the named scenario should be active for this run."""
    return ACTIVE_SCENARIO in {"", "all"} or ACTIVE_SCENARIO == name


LoginFlowUser.abstract = not _scenario_enabled("login")
RefreshFlowUser.abstract = not _scenario_enabled("refresh")
OTPLoginFlowUser.abstract = not _scenario_enabled("otp-login")
ActionOTPFlowUser.abstract = not _scenario_enabled("action-otp")
M2MTokenUser.abstract = not _scenario_enabled("m2m")
AdminPaginationUser.abstract = not _scenario_enabled("admin-pagination")
WebhookVolumeUser.abstract = not _scenario_enabled("webhook-volume")


@events.quitting.add_listener
def _on_quitting(environment, **_kwargs) -> None:
    """Enforce Step 14 pass/fail thresholds and runtime invariants at shutdown."""
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

    selected_tags = _selected_tags(environment)
    if "admin-pagination" in selected_tags and _admin_pagination_error is not None:
        print(f"[loadtest] admin pagination invariant failed: {_admin_pagination_error}")
        environment.process_exit_code = 1
