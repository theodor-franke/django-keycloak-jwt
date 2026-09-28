from __future__ import annotations

import os
import time
from collections.abc import Callable
from typing import Any

import pytest
import requests

KC_URL = os.environ.get("KC_URL", "http://localhost:8080")
KC_MGMT_URL = os.environ.get("KC_MGMT_URL", "http://localhost:9000")
REALM = "test"

TOKEN_URL = f"{KC_URL}/realms/{REALM}/protocol/openid-connect/token"
ADMIN_TOKEN_URL = f"{KC_URL}/realms/master/protocol/openid-connect/token"
ADMIN_REALM_API = f"{KC_URL}/admin/realms/{REALM}"

KC_ADMIN_USERNAME = os.environ.get("KC_BOOTSTRAP_ADMIN_USERNAME", "admin")
KC_ADMIN_PASSWORD = os.environ.get("KC_BOOTSTRAP_ADMIN_PASSWORD", "admin")


def _wait_for_keycloak(timeout: float = 120) -> None:
    deadline = time.monotonic() + timeout
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            response = requests.get(f"{KC_MGMT_URL}/health/ready", timeout=2)
            if response.status_code == 200:
                return
        except requests.RequestException as exc:
            last_exc = exc
        time.sleep(2)
    raise RuntimeError(f"Keycloak did not become ready within {timeout}s") from last_exc


@pytest.fixture(scope="session", autouse=True)
def _keycloak_ready() -> None:
    if os.environ.get("SKIP_KEYCLOAK_WAIT"):
        return
    _wait_for_keycloak()


def _password_grant(client_id: str, username: str, password: str, **extra: Any) -> dict[str, Any]:
    data = {
        "grant_type": "password",
        "client_id": client_id,
        "username": username,
        "password": password,
        "scope": "openid",
        **extra,
    }
    response = requests.post(TOKEN_URL, data=data, timeout=10)
    response.raise_for_status()
    result: dict[str, Any] = response.json()
    return result


TokenGetter = Callable[..., str]


@pytest.fixture
def get_token() -> TokenGetter:
    def _get_token(client_id: str, username: str, password: str, **extra: Any) -> str:
        return _password_grant(client_id, username, password, **extra)["access_token"]

    return _get_token


@pytest.fixture
def alice_token(get_token: TokenGetter) -> str:
    return get_token("frontend", "alice", "alice-pass")


@pytest.fixture
def bob_token(get_token: TokenGetter) -> str:
    return get_token("frontend", "bob", "bob-pass")


def admin_token() -> str:
    data = {
        "grant_type": "password",
        "client_id": "admin-cli",
        "username": KC_ADMIN_USERNAME,
        "password": KC_ADMIN_PASSWORD,
    }
    response = requests.post(ADMIN_TOKEN_URL, data=data, timeout=10)
    response.raise_for_status()
    result: dict[str, Any] = response.json()
    return str(result["access_token"])


@pytest.fixture
def admin_headers() -> dict[str, str]:
    return {"Authorization": f"Bearer {admin_token()}"}


@pytest.fixture
def realm_internal_id(admin_headers: dict[str, str]) -> str:
    response = requests.get(ADMIN_REALM_API, headers=admin_headers, timeout=10)
    response.raise_for_status()
    return str(response.json()["id"])
